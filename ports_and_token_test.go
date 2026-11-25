package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestResolveAgentTokenPersistenceAndRotation(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Explicit token is returned without persisting
	explicit, path, err := resolveAgentToken("custom-explicit-token", tmpDir, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if explicit != "custom-explicit-token" || path != "" {
		t.Fatalf("expected explicit token without path, got %q path=%q", explicit, path)
	}

	// 2. First persistent call creates a 32-char hex token on disk (0600)
	tok1, path1, err := resolveAgentToken("", tmpDir, false, false)
	if err != nil {
		t.Fatalf("resolveAgentToken failed: %v", err)
	}
	if len(tok1) != 32 {
		t.Fatalf("expected 32-char hex token, got len=%d (%q)", len(tok1), tok1)
	}
	if path1 == "" {
		t.Fatalf("expected non-empty persisted token path")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path1)
		if err != nil {
			t.Fatalf("stat failed: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
		}
	}

	// 3. Second call reuses the exact same token
	tok2, _, err := resolveAgentToken("", tmpDir, false, false)
	if err != nil {
		t.Fatalf("second resolveAgentToken failed: %v", err)
	}
	if tok2 != tok1 {
		t.Fatalf("expected persisted token reuse (%q), got %q", tok1, tok2)
	}

	// 4. Rotation generates a brand-new token and persists it
	tok3, _, err := resolveAgentToken("", tmpDir, false, true)
	if err != nil {
		t.Fatalf("rotate resolveAgentToken failed: %v", err)
	}
	if tok3 == tok1 || len(tok3) != 32 {
		t.Fatalf("expected rotated 32-char token different from %q, got %q", tok1, tok3)
	}
	tok4, _, _ := resolveAgentToken("", tmpDir, false, false)
	if tok4 != tok3 {
		t.Fatalf("expected rotated token to be persisted (%q), got %q", tok3, tok4)
	}

	// 5. Ephemeral mode returns empty string (NewAgentServer generates in-memory)
	eph, ephPath, err := resolveAgentToken("", tmpDir, true, false)
	if err != nil || eph != "" || ephPath != "" {
		t.Fatalf("expected empty ephemeral result, got tok=%q path=%q err=%v", eph, ephPath, err)
	}
}

func TestHandlePortListAuthAndSuccess(t *testing.T) {
	agent := NewAgentServer("port-test-token-1234567890abcdef", false)
	handler := agent.Routes()

	// 1. Unauthenticated request -> 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9921/api/ports/list", nil)
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", recUnauth.Code)
	}

	// 2. POST -> 405 Method Not Allowed
	reqPost := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9921/api/ports/list", nil)
	reqPost.Header.Set("X-EF-Token", agent.Token)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST, got %d", recPost.Code)
	}

	// 3. Authenticated GET -> 200 with structured JSON
	reqOk := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9921/api/ports/list", nil)
	reqOk.Header.Set("X-EF-Token", agent.Token)
	recOk := httptest.NewRecorder()
	handler.ServeHTTP(recOk, reqOk)
	if recOk.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated GET, got %d: %s", recOk.Code, recOk.Body.String())
	}

	var payload struct {
		Status  string              `json:"status"`
		OS      string              `json:"os"`
		Raw     string              `json:"raw"`
		PortMap map[string][]string `json:"portMap"`
	}
	if err := json.Unmarshal(recOk.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if payload.Status != "success" || payload.OS == "" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestProxyPreservesMultiHeadersAndCorsMaxAge(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid=abc; Path=/")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		w.Header().Set("X-Custom-Multi", "v1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	agent := NewAgentServer("proxy-hdr-token-0123456789abcdef", false)
	handler := agent.Routes()

	// 1. Preflight OPTIONS includes Access-Control-Max-Age: 600
	optReq := httptest.NewRequest(http.MethodOptions, "http://127.0.0.1:9921/api/proxy", nil)
	optReq.Header.Set("Origin", "https://every-forge.com")
	optRec := httptest.NewRecorder()
	handler.ServeHTTP(optRec, optReq)
	if optRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS, got %d", optRec.Code)
	}
	if optRec.Header().Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("expected Access-Control-Max-Age=600, got %q", optRec.Header().Get("Access-Control-Max-Age"))
	}

	// 2. Proxy POST preserves rawHeaders slice for Set-Cookie
	bodyBytes, _ := json.Marshal(ProxyRequest{
		URL:    upstream.URL,
		Method: "GET",
	})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9921/api/proxy", bytes.NewReader(bodyBytes))
	req.Header.Set("Origin", "https://every-forge.com")
	req.Header.Set("X-EF-Token", agent.Token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from proxy, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		StatusCode int                 `json:"statusCode"`
		Headers    map[string]string   `json:"headers"`
		RawHeaders map[string][]string `json:"rawHeaders"`
		Body       string              `json:"body"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid proxy json: %v", err)
	}
	cookies := resp.RawHeaders["Set-Cookie"]
	if len(cookies) != 2 || !strings.Contains(cookies[0], "sid=abc") || !strings.Contains(cookies[1], "theme=dark") {
		t.Fatalf("expected 2 Set-Cookie entries in rawHeaders, got %#v", cookies)
	}
}
