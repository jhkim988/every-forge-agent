package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- A1: PID validation extracted into a pure function ---

func TestValidatePid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1", true},
		{"42", true},
		{"4194304", true}, // 2^22, macOS pid_max upper bound
		{"0", false},      // process group of caller
		{"-1", false},     // signal broadcast
		{"-42", false},
		{"4194305", false}, // above pid_max
		{"99999999999999", false},
		{"abc", false},
		{"12x", false},
		{"", false},
		{" 12 ", false}, // whitespace must not slip through
	}
	for _, c := range cases {
		got := validatePid(c.in)
		if got != c.want {
			t.Errorf("validatePid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// --- A2: strict origin matching (hostname equality, no prefix/suffix tricks) ---

func TestIsAllowedOriginStrict(t *testing.T) {
	cases := []struct {
		origin string
		dev    bool
		want   bool
	}{
		{"", false, true}, // non-CORS request (same-origin tool / curl)
		{"https://every-forge.com", false, true},
		{"https://www.every-forge.com", false, true},
		{"http://localhost:4321", false, true},
		{"http://localhost", false, true},
		{"http://127.0.0.1:9921", false, true},
		{"http://[::1]:9921", false, true},

		// Attacker look-alikes MUST be rejected (prefix/suffix matching let these through)
		{"http://localhost.evil.com", false, false},
		{"http://localhost.evil.com", true, false},
		{"http://127.0.0.1.attacker.io", false, false},
		{"https://every-forge.com.evil.com", false, false},
		{"https://notlocalhost", false, false},

		// Dev-mode extras stay exact-host based
		{"https://preview.every-forge.com", true, true},
		{"https://feature-x.vercel.app", true, true},
		{"https://preview.every-forge.com", false, false},
		{"https://evil.vercel.app.evil.com", true, false},
		{"https://external-domain.com", false, false},
	}
	for _, c := range cases {
		if got := isAllowedOrigin(c.origin, c.dev); got != c.want {
			t.Errorf("isAllowedOrigin(%q, dev=%v) = %v, want %v", c.origin, c.dev, got, c.want)
		}
	}
}

// --- A3: DNS-rebinding defense via Host header validation ---

func TestValidLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:9921", true},
		{"localhost:9921", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"[::1]:9921", true},
		{"[::1]", true},
		{"LOCALHOST:8080", true}, // case-insensitive
		{"evil.com", false},
		{"attacker.local:9921", false},
		{"localhost.evil.com:9921", false},
		{"", true}, // HTTP/1.0-style omission tolerated
	}
	for _, c := range cases {
		if got := validLoopbackHost(c.host); got != c.want {
			t.Errorf("validLoopbackHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestRebindingHostRejected(t *testing.T) {
	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	for _, path := range []string{"/api/health", "/api/proxy"} {
		method := http.MethodGet
		var body io.Reader
		if path == "/api/proxy" {
			method = http.MethodPost
			body = strings.NewReader(`{"url":"http://internal.corp/secret"}`)
		}
		req, _ := http.NewRequest(method, ts.URL+path, body)
		req.Header.Set("Origin", "https://every-forge.com")
		req.Header.Set("X-EF-Token", "tok")
		req.Host = "evil.rebinder.test" // DNS-rebind style Host

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request to %s failed: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for non-loopback Host on %s, got %d", path, resp.StatusCode)
		}
	}
}

func TestLoopbackHostVariantsAccepted(t *testing.T) {
	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	// httptest binds 127.0.0.1:PORT; override Host to each accepted loopback spelling.
	for _, host := range []string{"localhost", "127.0.0.1", "[::1]"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed for host %s: %v", host, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for loopback Host %q, got %d", host, resp.StatusCode)
		}
	}
}

// --- Egress guard: cloud metadata endpoints must never be proxied ---

func TestProxyBlocksCloudMetadataEgress(t *testing.T) {
	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://100.100.100.200/v1/meta",
	} {
		payload := []byte(`{"url":"` + target + `","method":"GET"}`)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
		req.Header.Set("X-EF-Token", "tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request for %s failed: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for cloud metadata target %s, got %d", target, resp.StatusCode)
		}
	}

	// Normal intranet/loopback targets must remain allowed (core use case).
	payloadOK := []byte(`{"url":"http://127.0.0.1:59998/anything","method":"GET"}`)
	reqOK, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payloadOK))
	reqOK.Header.Set("X-EF-Token", "tok")
	respOK, err := http.DefaultClient.Do(reqOK)
	if err != nil {
		t.Fatalf("loopback proxy request failed: %v", err)
	}
	respOK.Body.Close()
	if respOK.StatusCode == http.StatusForbidden {
		t.Errorf("Loopback targets must not be blocked by the egress guard")
	}
}

// --- Token comparison must be constant-time ---

func TestAuthRejectsWrongToken(t *testing.T) {
	agent := NewAgentServer("correct-horse-battery-staple", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	for _, tok := range []string{"", "x", "correct-horse-battery-stapl", "correct-horse-battery-stapleX"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		if tok != "" {
			req.Header.Set("X-EF-Token", tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for token %q, got %d", tok, resp.StatusCode)
		}
	}
}

func TestEmptyTokenFailsClosed(t *testing.T) {
	agent := &AgentServer{} // zero value: no token configured
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", strings.NewReader(`{"url":"http://example.com"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for zero-value agent on protected endpoint, got %d", resp.StatusCode)
	}
}
