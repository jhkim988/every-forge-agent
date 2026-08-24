package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type AgentServer struct {
	Token         string
	DevMode       bool
	MaxProxyBytes int64 // proxy response cap; 0 => default (maxProxyResponseBytes)
}

func NewAgentServer(token string, devMode bool) *AgentServer {
	if token == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			panic("failed to generate random token: " + err.Error())
		}
		token = hex.EncodeToString(b)
	}
	return &AgentServer{Token: token, DevMode: devMode}
}

func (a *AgentServer) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public Health Check
	mux.HandleFunc("/api/health", a.hostMiddleware(a.corsMiddleware(a.handleHealth)))

	// Protected Endpoints (Require X-EF-Token or Bearer Token)
	mux.HandleFunc("/api/proxy", a.hostMiddleware(a.corsMiddleware(a.authMiddleware(a.handleProxy))))
	mux.HandleFunc("/api/process/list", a.hostMiddleware(a.corsMiddleware(a.authMiddleware(a.handleProcessList))))
	mux.HandleFunc("/api/process/kill", a.hostMiddleware(a.corsMiddleware(a.authMiddleware(a.handleProcessKill))))

	return mux
}

// hostMiddleware rejects requests whose Host header does not target the local
// loopback, defending against DNS-rebinding attacks where a public hostname
// resolves to 127.0.0.1.
func (a *AgentServer) hostMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validLoopbackHost(r.Host) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "host not allowed: agent only accepts loopback Host headers",
			})
			return
		}
		next(w, r)
	}
}

func isAllowedOrigin(origin string, isDev bool) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())

	// Always allow production official domains (exact host match)
	if host == "every-forge.com" || host == "www.every-forge.com" {
		return true
	}
	// Allow local loopback hosts only (exact match; blocks look-alikes such as
	// localhost.evil.com or 127.0.0.1.attacker.io)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	// In dev mode, allow preview deployments (exact host match on known suffixes)
	if isDev && (strings.HasSuffix(host, ".every-forge.com") || strings.HasSuffix(host, ".vercel.app")) {
		return true
	}
	return false
}

// validLoopbackHost reports whether the Host header targets the local loopback.
// This is a DNS-rebinding defense: a public hostname resolving to 127.0.0.1 must
// not reach the agent, even though the connection itself arrives from loopback.
func validLoopbackHost(hostHeader string) bool {
	if hostHeader == "" {
		// Tolerate HTTP/1.0-style requests without a Host header.
		return true
	}
	h := strings.ToLower(hostHeader)
	if i := strings.LastIndex(h, ":"); i != -1 && !strings.Contains(h[i:], "]") {
		h = h[:i] // strip port (careful with IPv6 brackets)
	}
	h = strings.Trim(h, "[]")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// validatePid reports whether pid is a positive integer within OS pid_t range.
// This blocks dangerous values such as -1 (signal broadcast on Unix) and 0
// (process group of the caller) before they ever reach the OS.
func validatePid(pid string) bool {
	pidNum, err := strconv.Atoi(pid)
	return err == nil && pidNum > 0 && pidNum <= 4194304 // 4194304 = 2^22, default macOS pid_max
}

// blockedMetadataHosts are cloud instance metadata endpoints (AWS/GCP/Azure/
// Alibaba). A paired browser page tricked into proxying these could harvest
// instance credentials; intranet testing (the agent's purpose) never needs
// them. Only exact IP-literal hosts are blocked — private LAN ranges stay
// reachable because intranet testing is the core use case.
var blockedMetadataHosts = map[string]bool{
	"169.254.169.254": true, // AWS / GCP / Azure / OpenStack
	"fd00:ec2::254":   true, // GCP IPv6 metadata
	"100.100.100.200": true, // Alibaba Cloud
}

func isBlockedProxyTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false // let http.NewRequest produce the proper client error
	}
	host := strings.ToLower(u.Hostname())
	if i := strings.LastIndex(host, ":"); i != -1 && strings.Contains(host, ":") {
		_ = i // IPv6 hostnames arrive bracket-free from url.Parse Hostname()
	}
	return blockedMetadataHosts[host]
}

func (a *AgentServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if !isAllowedOrigin(origin, a.DevMode) {
			// Defense in depth: requests from non-whitelisted origins are rejected
			// outright instead of being processed with neutralized CORS headers.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "origin not allowed",
			})
			return
		}

		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
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
		// Fail closed when no token is configured: an agent without a token must
		// never serve protected endpoints (defense against future refactoring
		// reintroducing a tokenless mode).
		if a.Token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "agent has no security token configured; refusing to serve protected endpoints",
			})
			return
		}

		token := r.Header.Get("X-EF-Token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(a.Token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Unauthorized. Missing or invalid X-EF-Token header.",
				"hint":  "Pair this browser session using the token printed in your local-agent console.",
			})
			return
		}
		next(w, r)
	}
}

func (a *AgentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]interface{}{
		"status":    "running",
		"agent":     "every-forge-agent",
		"version":   version,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"timestamp": time.Now().Unix(),
	}
	if a.DevMode {
		// In dev mode, we can optionally show the token for debugging, but it's a security risk.
		// For safety, we omit it in all modes.
		// data["token"] = a.Token
	}
	json.NewEncoder(w).Encode(data)
}

type ProxyRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

const maxProxyResponseBytes = 10 << 20 // 10 MB cap on proxied response bodies

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "1.0.0"

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

	// Egress guard: never proxy to cloud instance metadata endpoints.
	if isBlockedProxyTarget(reqData.URL) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "target URL is blocked (cloud metadata endpoints are not proxyable)",
			"targetURL": reqData.URL,
		})
		return
	}

	// Do not follow redirects: surface the raw redirect back to the caller so
	// forwarded headers and credentials never leak to an unvalidated Location.
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

	start := time.Now()
	resp, err := client.Do(outReq)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      err.Error(),
			"durationMs": duration,
			"targetURL":  reqData.URL,
		})
		return
	}
	defer resp.Body.Close()

	// Cap buffered response size to protect the agent from OOM on huge targets.
	limit := int64(maxProxyResponseBytes)
	if a.MaxProxyBytes > 0 {
		limit = a.MaxProxyBytes
	}
	respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if readErr == nil && int64(len(respBytes)) > limit {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      fmt.Sprintf("response body too large (limit %d bytes)", limit),
			"durationMs": duration,
			"targetURL":  reqData.URL,
		})
		return
	}

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
	Memory  string `json:"memory,omitempty"`
	Session string `json:"session,omitempty"`
	User    string `json:"user,omitempty"`
	CPU     string `json:"cpu,omitempty"`
}

// parseProcessList converts raw OS process listings into structured items.
// Supports macOS/Linux `ps` output and Windows `tasklist /FO CSV /NH`.
func parseProcessList(raw string, goos string) []ProcessItem {
	items := []ProcessItem{}
	if goos == "windows" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "\"") {
				continue
			}
			fields := strings.Split(line, "\",\"")
			if len(fields) < 5 {
				continue
			}
			items = append(items, ProcessItem{
				Name:    strings.Trim(fields[0], "\""),
				PID:     strings.Trim(fields[1], "\""),
				Session: strings.Trim(fields[2], "\""),
				Memory:  strings.Trim(fields[4], "\""),
			})
		}
		return items
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		items = append(items, ProcessItem{
			PID:    fields[0],
			User:   fields[1],
			CPU:    fields[2],
			Memory: fields[3],
			Name:   strings.Join(fields[4:], " "),
		})
	}
	return items
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
		"os":        runtime.GOOS,
		"raw":       string(out),
		"processes": parseProcessList(string(out), runtime.GOOS),
		"status":    "success",
	})
}

func (a *AgentServer) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	pid := r.URL.Query().Get("pid")
	if pid == "" {
		http.Error(w, "Missing pid parameter", http.StatusBadRequest)
		return
	}

	// Validate PID strictly: must be a positive integer within OS pid_t range.
	// This blocks dangerous values such as -1 (signal broadcast on Unix) and 0
	// (process group of the caller) before they ever reach the OS.
	if !validatePid(pid) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "invalid pid: must be a positive integer",
			"pid":    pid,
		})
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

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Agent server error: %v", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\n  Shutting down gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
