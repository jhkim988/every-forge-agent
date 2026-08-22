package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

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

func EchoRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", corsHandler(handleEcho))
	mux.HandleFunc("/echo", corsHandler(handleEcho))
	mux.HandleFunc("/api/echo", corsHandler(handleEcho))
	return mux
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

	bodyBytes, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

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
	port := os.Getenv("PORT")
	if port == "" {
		port = "9922"
	}

	fmt.Println("======================================================")
	fmt.Println("  📡 Every-Forge Development HTTP Echo Server")
	fmt.Println("======================================================")
	fmt.Printf("  • Listening On: http://127.0.0.1:%s\n", port)
	fmt.Printf("  • Echo Endpoint: http://127.0.0.1:%s/echo\n", port)
	fmt.Println("  • CORS: Fully Permissive (Access-Control-Allow-Origin: *)")
	fmt.Println("======================================================")
	fmt.Println("  Ready for cURL Studio live testing. Press Ctrl+C to stop.")

	server := &http.Server{
		Addr:         "127.0.0.1:" + port,
		Handler:      EchoRouter(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Echo server error: %v", err)
	}
}
