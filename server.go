package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "1.0.0"

const maxProxyResponseBytes = 10 << 20 // 10 MB cap on proxied response bodies

type AgentServer struct {
	Token               string
	DevMode             bool
	MaxProxyBytes       int64 // proxy response cap; 0 => default (maxProxyResponseBytes)
	MaxRequestBodyBytes int64 // proxy request body cap; 0 => default (10 << 20)
	httpClient          *http.Client
	cronMu              sync.Mutex
	CrontabReadFunc     func() (string, error)
	CrontabWriteFunc    func(content string) error
}

func NewAgentServer(token string, devMode bool) *AgentServer {
	if token == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			panic("failed to generate random token: " + err.Error())
		}
		token = hex.EncodeToString(b)
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if isBlockedMetadataIP(ip) {
				return errors.New("connection blocked: target address is cloud metadata")
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &AgentServer{
		Token:               token,
		DevMode:             devMode,
		MaxRequestBodyBytes: 10 << 20,
		httpClient:          client,
	}
}

// public wraps a handler with host and cors middleware.
func (a *AgentServer) public(next http.HandlerFunc) http.HandlerFunc {
	return a.hostMiddleware(a.corsMiddleware(next))
}

// protected wraps a handler with host, cors, and auth middleware.
func (a *AgentServer) protected(next http.HandlerFunc) http.HandlerFunc {
	return a.hostMiddleware(a.corsMiddleware(a.authMiddleware(next)))
}

func (a *AgentServer) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public Health Check
	mux.HandleFunc("/api/health", a.public(a.handleHealth))

	// Protected Proxy Endpoint
	mux.HandleFunc("/api/proxy", a.protected(a.handleProxy))

	// Protected Process Endpoints
	mux.HandleFunc("/api/process/list", a.protected(a.handleProcessList))
	mux.HandleFunc("/api/process/kill", a.protected(a.handleProcessKill))

	// Protected Cron Endpoints
	mux.HandleFunc("/api/cron/list", a.protected(a.handleCronList))
	mux.HandleFunc("/api/cron/save", a.protected(a.handleCronSave))
	mux.HandleFunc("/api/cron/delete", a.protected(a.handleCronDelete))

	return mux
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
	json.NewEncoder(w).Encode(data)
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

	maxReqBytes := a.MaxRequestBodyBytes
	if maxReqBytes <= 0 {
		maxReqBytes = 10 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxReqBytes)

	var reqData ProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "request body exceeds maximum allowed size",
			})
			return
		}
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

	client := a.httpClient
	if client == nil {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					host = address
				}
				ip := net.ParseIP(strings.Trim(host, "[]"))
				if isBlockedMetadataIP(ip) {
					return errors.New("connection blocked: target address is cloud metadata")
				}
				return nil
			},
		}
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
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
