package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "v1.2.1"

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

func newSafeProxyHTTPClient() *http.Client {
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
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil, // direct egress only so dialer.Control always inspects destination IP
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

func (a *AgentServer) proxyHTTPClient() *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return newSafeProxyHTTPClient()
}

func NewAgentServer(token string, devMode bool) *AgentServer {
	if token == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			panic("failed to generate random token: " + err.Error())
		}
		token = hex.EncodeToString(b)
	}
	return &AgentServer{
		Token:               token,
		DevMode:             devMode,
		MaxRequestBodyBytes: 10 << 20,
		httpClient:          newSafeProxyHTTPClient(),
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

	// Protected Process & Ports Endpoints
	mux.HandleFunc("/api/process/list", a.protected(a.handleProcessList))
	mux.HandleFunc("/api/process/kill", a.protected(a.handleProcessKill))
	mux.HandleFunc("/api/ports/list", a.protected(a.handlePortList))

	// Protected Cron Endpoints
	mux.HandleFunc("/api/cron/list", a.protected(a.handleCronList))
	mux.HandleFunc("/api/cron/save", a.protected(a.handleCronSave))
	mux.HandleFunc("/api/cron/delete", a.protected(a.handleCronDelete))

	return mux
}

func (a *AgentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]interface{}{
		"status":        "running",
		"agent":         "every-forge-agent",
		"version":       version,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"timestamp":     time.Now().Unix(),
		"authenticated": a.isAuthorized(r),
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

	parsedTarget, parseErr := url.Parse(strings.TrimSpace(reqData.URL))
	if parseErr != nil || (!strings.EqualFold(parsedTarget.Scheme, "http") && !strings.EqualFold(parsedTarget.Scheme, "https")) || parsedTarget.Hostname() == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "invalid target URL: scheme must be http or https",
			"targetURL": reqData.URL,
		})
		return
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

	client := a.proxyHTTPClient()

	var bodyReader io.Reader
	if reqData.Body != "" {
		bodyReader = strings.NewReader(reqData.Body)
	}

	outReq, err := http.NewRequestWithContext(r.Context(), method, reqData.URL, bodyReader)
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
	respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	duration = time.Since(start).Milliseconds()
	if int64(len(respBytes)) > limit {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      fmt.Sprintf("response body too large (limit %d bytes)", limit),
			"durationMs": duration,
			"targetURL":  reqData.URL,
		})
		return
	}
	if readErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "failed to read upstream response body: " + readErr.Error(),
			"durationMs": duration,
			"targetURL":  reqData.URL,
		})
		return
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	bodyEncoding := "utf-8"
	bodyBase64 := ""
	if !utf8.Valid(respBytes) {
		bodyEncoding = "base64"
		bodyBase64 = base64.StdEncoding.EncodeToString(respBytes)
	}

	payload := map[string]interface{}{
		"statusCode":   resp.StatusCode,
		"statusText":   resp.Status,
		"headers":      respHeaders,
		"rawHeaders":   resp.Header,
		"body":         string(respBytes),
		"bodyEncoding": bodyEncoding,
		"durationMs":   duration,
		"sizeBytes":    len(respBytes),
	}
	if bodyBase64 != "" {
		payload["bodyBase64"] = bodyBase64
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}
