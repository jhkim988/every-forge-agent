package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const maxEchoRequestBytes = 1 << 20 // 1 MB cap on echoed request bodies

type EchoResponse struct {
	Timestamp int64             `json:"timestamp"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Query     map[string]string `json:"query"`
	Body      string            `json:"body,omitempty"`
	ClientIP  string            `json:"clientIp"`
}

func isLoopbackEchoHost(hostHeader string) bool {
	if hostHeader == "" {
		return true
	}
	if strings.ContainsAny(hostHeader, "@/\\?# \t\r\n") {
		return false
	}
	h := strings.ToLower(hostHeader)
	if h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1" {
		return true
	}
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return false
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func EchoRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", hostGuard(corsHandler(handleEcho)))
	mux.HandleFunc("/echo", hostGuard(corsHandler(handleEcho)))
	mux.HandleFunc("/api/echo", hostGuard(corsHandler(handleEcho)))
	return mux
}

func hostGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackEchoHost(r.Host) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "host not allowed: echo server only accepts loopback Host headers",
			})
			return
		}
		next(w, r)
	}
}

func corsHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow Any Origin for Echo Development Testing
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Expose-Headers", "*")
		// Chrome Private Network Access (PNA) Support (HTTPS -> Localhost)
		w.Header().Set("Access-Control-Allow-Private-Network", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	query := make(map[string]string)
	for k, v := range r.URL.Query() {
		query[k] = strings.Join(v, ", ")
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEchoRequestBytes)
	defer r.Body.Close()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "echo body exceeds maximum allowed size (1 MB)",
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "failed to read request body: " + err.Error(),
		})
		return
	}

	resp := EchoResponse{
		Timestamp: time.Now().UnixMilli(),
		Method:    r.Method,
		URL:       r.RequestURI,
		Path:      r.URL.Path,
		Headers:   headers,
		Query:     query,
		Body:      string(bodyBytes),
		ClientIP:  r.RemoteAddr,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func main() {
	portFlag := flag.String("port", "", "Server port (default: 9922)")
	flag.Parse()

	port := *portFlag
	if port == "" {
		port = os.Getenv("PORT")
		if port == "" {
			port = "9922"
		}
	}

	fmt.Println("======================================================")
	fmt.Println("  📡 Every-Forge Development HTTP Echo Server")
	fmt.Println("======================================================")
	fmt.Printf("  • Listening On: http://127.0.0.1:%s\n", port)
	fmt.Printf("  • Echo Endpoint: http://127.0.0.1:%s/echo\n", port)
	fmt.Println("  • CORS: Fully Permissive (Access-Control-Allow-Origin: *)")
	fmt.Println("  • Body Limit: 1 MB | Loopback Host Guard Enabled")
	fmt.Println("======================================================")
	fmt.Println("  Ready for cURL Studio live testing. Press Ctrl+C to stop.")

	server := &http.Server{
		Addr:              "127.0.0.1:" + port,
		Handler:           EchoRouter(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Echo server error: %v", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\n  Shutting down echo server gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
