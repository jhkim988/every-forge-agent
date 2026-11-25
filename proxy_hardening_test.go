package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyHardening_SchemeAllowlist(t *testing.T) {
	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	badSchemes := []string{
		"file:///etc/passwd",
		"ftp://127.0.0.1:21/pub",
		"gopher://127.0.0.1:70/_",
		"ws://127.0.0.1:8080/ws",
		"javascript:alert(1)",
		"127.0.0.1:8080/no-scheme",
	}

	for _, u := range badSchemes {
		if !isBlockedProxyTarget(u) {
			t.Errorf("isBlockedProxyTarget(%q) = false, want true", u)
		}
		payload, _ := json.Marshal(ProxyRequest{URL: u, Method: "GET"})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
		req.Header.Set("X-EF-Token", "tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed for %q: %v", u, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
			t.Errorf("URL %q returned status %d, want 400 or 403", u, resp.StatusCode)
		}
	}
}

func TestProxyHardening_TruncatedUpstreamBodyReturns502(t *testing.T) {
	// Upstream server advertises Content-Length: 1000 but hijacks and closes after 10 bytes -> unexpected EOF
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: text/plain\r\n\r\nshort-body"))
		conn.Close()
	}()

	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	payload, _ := json.Marshal(ProxyRequest{
		URL:    "http://" + ln.Addr().String() + "/truncated",
		Method: "GET",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
	req.Header.Set("X-EF-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway on truncated upstream stream, got %d", resp.StatusCode)
	}
}

func TestProxyHardening_BinaryBodyPreservedAsBase64(t *testing.T) {
	rawBin := []byte{0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0x80}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rawBin)
	}))
	defer upstream.Close()

	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	payload, _ := json.Marshal(ProxyRequest{URL: upstream.URL, Method: "GET"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
	req.Header.Set("X-EF-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call failed: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if data["bodyEncoding"] != "base64" {
		t.Fatalf("expected bodyEncoding=base64 for non-UTF8 bytes, got %v", data["bodyEncoding"])
	}
	b64, _ := data["bodyBase64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || !bytes.Equal(decoded, rawBin) {
		t.Fatalf("decoded base64 %x != original %x (err=%v)", decoded, rawBin, err)
	}
}

func TestProxyHardening_ContextCancellationPropagates(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()

	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	payload, _ := json.Marshal(ProxyRequest{URL: upstream.URL, Method: "GET"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
	req.Header.Set("X-EF-Token", "tok")

	go func() {
		<-started
		cancel()
	}()

	_, _ = http.DefaultClient.Do(req)

	select {
	case <-canceled:
		// Upstream received cancellation promptly
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request context was not canceled within 2s after client abort")
	}
}

func TestProxyHardening_IgnoresEnvHTTPProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct-ok"))
	}))
	defer upstream.Close()

	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	payload, _ := json.Marshal(ProxyRequest{URL: upstream.URL, Method: "GET"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
	req.Header.Set("X-EF-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy call failed: %v", err)
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	if data["statusCode"] != float64(200) || !strings.Contains(data["body"].(string), "direct-ok") {
		t.Fatalf("expected direct connection ignoring HTTP_PROXY, got: %+v", data)
	}
}
