package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type AgentServer struct {
	Token   string
	DevMode bool
}

func NewAgentServer(token string, devMode bool) *AgentServer {
	return &AgentServer{Token: token, DevMode: devMode}
}

func (a *AgentServer) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public Health Check
	mux.HandleFunc("/api/health", a.corsMiddleware(a.handleHealth))

	// Protected Endpoints (Require X-EF-Token or Bearer Token)
	mux.HandleFunc("/api/proxy", a.corsMiddleware(a.authMiddleware(a.handleProxy)))
	mux.HandleFunc("/api/process/list", a.corsMiddleware(a.authMiddleware(a.handleProcessList)))
	mux.HandleFunc("/api/process/kill", a.corsMiddleware(a.authMiddleware(a.handleProcessKill)))

	return mux
}

func isAllowedOrigin(origin string, isDev bool) bool {
	if origin == "" {
		return true
	}
	// Always allow production official domains
	if origin == "https://every-forge.com" || origin == "https://www.every-forge.com" {
		return true
	}
	// Allow localhost and local loopback in development / dev flag or local ports
	if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
		return true
	}
	// In dev mode, allow any local subdomains or vercel preview deployments
	if isDev && (strings.HasSuffix(origin, ".every-forge.com") || strings.HasSuffix(origin, ".vercel.app")) {
		return true
	}
	return false
}

func (a *AgentServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		if isAllowedOrigin(origin, a.DevMode) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "https://every-forge.com")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-EF-Token, Authorization, Access-Control-Request-Private-Network")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		// Chrome Private Network Access (PNA) Preflight Support (https -> localhost)
		w.Header().Set("Access-Control-Allow-Private-Network", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func (a *AgentServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no token was configured by flag, allow seamless zero-config local loopback usage
		if a.Token == "" {
			next(w, r)
			return
		}

		token := r.Header.Get("X-EF-Token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token != a.Token {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Unauthorized. Missing or invalid X-EF-Token header.",
				"hint":    "Pair this browser session using the token printed in your local-agent console.",
			})
			return
		}
		next(w, r)
	}
}

func (a *AgentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "running",
		"agent":     "every-forge-agent",
		"version":   "1.0.0",
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"token":     a.Token,
		"timestamp": time.Now().Unix(),
	})
}

type ProxyRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func (a *AgentServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData ProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	method := strings.ToUpper(reqData.Method)
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if reqData.Body != "" {
		bodyReader = strings.NewReader(reqData.Body)
	}

	outReq, err := http.NewRequest(method, reqData.URL, bodyReader)
	if err != nil {
		http.Error(w, "Failed to create target request: "+err.Error(), http.StatusBadRequest)
		return
	}

	for k, v := range reqData.Headers {
		outReq.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	start := time.Now()
	resp, err := client.Do(outReq)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":        err.Error(),
			"durationMs":   duration,
			"targetURL":    reqData.URL,
		})
		return
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"statusCode": resp.StatusCode,
		"statusText": resp.Status,
		"headers":    respHeaders,
		"body":       string(respBytes),
		"durationMs": duration,
		"sizeBytes":  len(respBytes),
	})
}

type ProcessItem struct {
	PID     string `json:"pid"`
	Name    string `json:"name"`
	Memory  string `json:"memory"`
	Session string `json:"session,omitempty"`
}

func (a *AgentServer) handleProcessList(w http.ResponseWriter, r *http.Request) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
	} else {
		cmd = exec.Command("ps", "-eo", "pid,user,%cpu,%mem,comm")
	}

	out, err := cmd.Output()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to inspect processes: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"os":     runtime.GOOS,
		"raw":    string(out),
		"status": "success",
	})
}

func (a *AgentServer) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	pid := r.URL.Query().Get("pid")
	if pid == "" {
		http.Error(w, "Missing pid parameter", http.StatusBadRequest)
		return
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("taskkill", "/F", "/PID", pid)
	} else {
		cmd = exec.Command("kill", "-9", pid)
	}

	out, err := cmd.CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"output": string(out),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "killed",
		"pid":    pid,
		"output": string(out),
	})
}

func main() {
	portFlag := flag.String("port", "", "Server port (default: 9921)")
	tokenFlag := flag.String("token", "", "Custom security token (optional)")
	devFlag := flag.Bool("dev", false, "Enable development mode (allows preview subdomains)")
	flag.Parse()

	port := *portFlag
	if port == "" {
		port = os.Getenv("PORT")
		if port == "" {
			port = "9921"
		}
	}

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("EF_TOKEN")
	}

	isDev := *devFlag || os.Getenv("EF_DEV") == "true" || os.Getenv("NODE_ENV") == "development"

	agent := NewAgentServer(token, isDev)

	fmt.Println("======================================================")
	fmt.Println("  ⚡ Every-Forge Ultra-Lightweight Local Bridge Agent")
	fmt.Println("======================================================")
	fmt.Printf("  • Environment: %s\n", map[bool]string{true: "Development", false: "Production"}[isDev])
	fmt.Printf("  • Listening On: http://127.0.0.1:%s\n", port)
	fmt.Printf("  • Allowed Origins: https://every-forge.com, https://www.every-forge.com, http://localhost:*\n")
	fmt.Printf("  • Security Token (X-EF-Token): %s\n", agent.Token)
	fmt.Println("  • Features: Native CORS Proxy | Process Inspection | Chrome PNA")
	fmt.Println("======================================================")
	fmt.Println("  Ready. Press Ctrl+C to terminate.")

	server := &http.Server{
		Addr:         "127.0.0.1:" + port,
		Handler:      agent.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 35 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Agent server error: %v", err)
	}
}
