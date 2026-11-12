package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalAgentServer(t *testing.T) {
	agent := NewAgentServer("test-secret-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	t.Run("NewAgentServer token generation", func(t *testing.T) {
		autoAgent := NewAgentServer("", false)
		if len(autoAgent.Token) != 32 {
			t.Errorf("Expected 32-char hex token for empty init, got len %d (%s)", len(autoAgent.Token), autoAgent.Token)
		}

		customAgent := NewAgentServer("custom-token-123", false)
		if customAgent.Token != "custom-token-123" {
			t.Errorf("Expected custom token, got %s", customAgent.Token)
		}
	})

	t.Run("Production Origin Whitelist (every-forge.com & www.every-forge.com)", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/health", nil)
		req.Header.Set("Origin", "https://every-forge.com")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("OPTIONS preflight failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.Header.Get("Access-Control-Allow-Origin") != "https://every-forge.com" {
			t.Errorf("Expected allowed origin https://every-forge.com, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
		}
		if resp.Header.Get("Access-Control-Allow-Private-Network") != "true" {
			t.Errorf("Expected PNA header true, got %s", resp.Header.Get("Access-Control-Allow-Private-Network"))
		}
	})

	t.Run("Public Health Check /api/health", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
		if err != nil {
			t.Fatalf("Failed to create health request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			t.Fatalf("Failed to decode health response: %v", err)
		}

		if data["status"] != "running" {
			t.Errorf("Expected status running, got %v", data["status"])
		}
		if data["agent"] != "every-forge-agent" {
			t.Errorf("Expected agent every-forge-agent, got %v", data["agent"])
		}
		if data["version"] != "1.0.0" {
			t.Errorf("Expected version 1.0.0, got %v", data["version"])
		}
		if data["os"] == "" || data["arch"] == "" {
			t.Errorf("Expected non-empty os and arch telemetry, got os=%v, arch=%v", data["os"], data["arch"])
		}
		if _, ok := data["timestamp"].(float64); !ok {
			t.Errorf("Expected numeric timestamp, got %v", data["timestamp"])
		}
	})

	t.Run("CORS Preflight and Header Reflection", func(t *testing.T) {
		// OPTIONS request
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/health", nil)
		req.Header.Set("Origin", "http://localhost:4321")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("OPTIONS request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected status 204 for OPTIONS, got %d", resp.StatusCode)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost:4321" {
			t.Errorf("Expected CORS origin reflection http://localhost:4321, got %s", resp.Header.Get("Access-Control-Allow-Origin"))
		}
		if resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
			t.Errorf("Expected Allow-Credentials true, got %s", resp.Header.Get("Access-Control-Allow-Credentials"))
		}

		// Non-whitelisted external domain is rejected outright with 403
		reqOther, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/health", nil)
		reqOther.Header.Set("Origin", "https://external-domain.com")
		respOther, err := http.DefaultClient.Do(reqOther)
		if err != nil {
			t.Fatalf("OPTIONS request for external origin failed: %v", err)
		}
		defer respOther.Body.Close()
		if respOther.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for external origin, got %d", respOther.StatusCode)
		}
	})

	t.Run("Authentication Guard", func(t *testing.T) {
		// 1. Missing token
		req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		resp1, err := http.DefaultClient.Do(req1)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp1.Body.Close()
		if resp1.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for missing token, got %d", resp1.StatusCode)
		}

		// 2. Invalid X-EF-Token
		req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req2.Header.Set("X-EF-Token", "wrong-token-abc")
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for invalid X-EF-Token, got %d", resp2.StatusCode)
		}

		// 3. Valid X-EF-Token
		req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req3.Header.Set("X-EF-Token", "test-secret-token")
		resp3, err := http.DefaultClient.Do(req3)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp3.Body.Close()
		if resp3.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK for valid X-EF-Token, got %d", resp3.StatusCode)
		}

		// 4. Valid Bearer Token in Authorization header
		req4, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req4.Header.Set("Authorization", "Bearer test-secret-token")
		resp4, err := http.DefaultClient.Do(req4)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp4.Body.Close()
		if resp4.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK for valid Bearer token, got %d", resp4.StatusCode)
		}

		// 5. Invalid Bearer Token in Authorization header
		req5, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req5.Header.Set("Authorization", "Bearer invalid-token")
		resp5, err := http.DefaultClient.Do(req5)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp5.Body.Close()
		if resp5.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for invalid Bearer token, got %d", resp5.StatusCode)
		}
	})

	t.Run("CORS Native Proxy /api/proxy", func(t *testing.T) {
		// Target mock HTTP server
		targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Echo-Custom", r.Header.Get("X-Forward-Test"))
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"result":"target-reached","receivedMethod":"` + r.Method + `"}`))
		}))
		defer targetServer.Close()

		// 1. Valid POST proxy request
		proxyPayload := ProxyRequest{
			URL:     targetServer.URL,
			Method:  "POST",
			Headers: map[string]string{"X-Forward-Test": "EveryForgeProxy"},
			Body:    `{"name":"item1"}`,
		}
		bodyBytes, _ := json.Marshal(proxyPayload)

		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-EF-Token", "test-secret-token")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Proxy request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK response from proxy endpoint, got %d", resp.StatusCode)
		}

		var resData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&resData)

		if resData["statusCode"].(float64) != http.StatusCreated {
			t.Errorf("Expected proxied target status 201, got %v", resData["statusCode"])
		}
		headers := resData["headers"].(map[string]interface{})
		if headers["X-Echo-Custom"] != "EveryForgeProxy" {
			t.Errorf("Expected forwarded custom header, got %v", headers["X-Echo-Custom"])
		}
		if resData["sizeBytes"].(float64) <= 0 {
			t.Errorf("Expected sizeBytes > 0, got %v", resData["sizeBytes"])
		}

		// 2. Proxy request with non-POST method on /api/proxy endpoint
		reqGet, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/proxy", nil)
		reqGet.Header.Set("X-EF-Token", "test-secret-token")
		respGet, err := http.DefaultClient.Do(reqGet)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer respGet.Body.Close()
		if respGet.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 Method Not Allowed for GET /api/proxy, got %d", respGet.StatusCode)
		}

		// 3. Proxy request with invalid JSON payload
		reqBadJson, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader([]byte("{invalid-json")))
		reqBadJson.Header.Set("Content-Type", "application/json")
		reqBadJson.Header.Set("X-EF-Token", "test-secret-token")
		respBadJson, err := http.DefaultClient.Do(reqBadJson)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer respBadJson.Body.Close()
		if respBadJson.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for malformed JSON, got %d", respBadJson.StatusCode)
		}

		// 4. Proxy request to unreachable target server (Bad Gateway 502)
		unreachablePayload := ProxyRequest{
			URL:    "http://127.0.0.1:59999/unreachable",
			Method: "GET",
		}
		unreachableBytes, _ := json.Marshal(unreachablePayload)
		reqUnreach, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(unreachableBytes))
		reqUnreach.Header.Set("Content-Type", "application/json")
		reqUnreach.Header.Set("X-EF-Token", "test-secret-token")
		respUnreach, err := http.DefaultClient.Do(reqUnreach)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer respUnreach.Body.Close()
		if respUnreach.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected 502 Bad Gateway for unreachable target, got %d", respUnreach.StatusCode)
		}
	})

	t.Run("Process Inspection & Kill Endpoints", func(t *testing.T) {
		// Process List
		reqList, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		reqList.Header.Set("X-EF-Token", "test-secret-token")
		respList, err := http.DefaultClient.Do(reqList)
		if err != nil {
			t.Fatalf("Process list failed: %v", err)
		}
		defer respList.Body.Close()

		if respList.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for process list, got %d", respList.StatusCode)
		}
		var listData map[string]interface{}
		json.NewDecoder(respList.Body).Decode(&listData)
		if listData["status"] != "success" {
			t.Errorf("Expected status success, got %v", listData["status"])
		}

		// Process Kill: Missing PID parameter returns 400
		reqKillNoPid, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/process/kill", nil)
		reqKillNoPid.Header.Set("X-EF-Token", "test-secret-token")
		respKillNoPid, err := http.DefaultClient.Do(reqKillNoPid)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer respKillNoPid.Body.Close()
		if respKillNoPid.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for missing pid, got %d", respKillNoPid.StatusCode)
		}

		// Process Kill: Invalid PID execution handles error cleanly
		reqKillInvalid, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/process/kill?pid=99999999", nil)
		reqKillInvalid.Header.Set("X-EF-Token", "test-secret-token")
		respKillInvalid, err := http.DefaultClient.Do(reqKillInvalid)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer respKillInvalid.Body.Close()
		// Out-of-range PID (exceeds pid_max) is rejected by validation with 400,
		// never forwarded to the OS.
		if respKillInvalid.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 for out-of-range PID kill, got %d", respKillInvalid.StatusCode)
		}

		// Process Kill: Non-numeric PID must be rejected with 400 BEFORE reaching the OS.
		// Uses a harmless non-numeric value; dangerous values (-1) must never be executed.
		reqKillAlpha, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/process/kill?pid=abc", nil)
		reqKillAlpha.Header.Set("X-EF-Token", "test-secret-token")
		respKillAlpha, err := http.DefaultClient.Do(reqKillAlpha)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer respKillAlpha.Body.Close()
		if respKillAlpha.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for non-numeric pid 'abc', got %d", respKillAlpha.StatusCode)
		}

		// Process Kill: negative and out-of-range PIDs must be rejected with 400
		for _, badPid := range []string{"0", "-1"} {
			reqBad, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/process/kill?pid="+badPid, nil)
			reqBad.Header.Set("X-EF-Token", "test-secret-token")
			respBad, err := http.DefaultClient.Do(reqBad)
			if err != nil {
				t.Fatalf("request failed for pid %s: %v", badPid, err)
			}
			respBad.Body.Close()
			if respBad.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected 400 for pid %s, got %d", badPid, respBad.StatusCode)
			}
		}
	})
}

func TestForbiddenOriginRejected(t *testing.T) {
	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	for _, path := range []string{"/api/health", "/api/proxy"} {
		method := http.MethodGet
		if path == "/api/proxy" {
			method = http.MethodPost
		}
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request to %s failed: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		_ = body

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 for evil origin on %s, got %d", path, resp.StatusCode)
		}
	}
}

func TestProxySafetyLimits(t *testing.T) {
	agent := &AgentServer{Token: "tok", MaxProxyBytes: 1 << 20} // 1 MB cap for test
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	// 1. Oversized response body must be rejected, not buffered into memory
	big := make([]byte, 2<<20) // 2 MB > injected 1 MB cap
	for i := range big {
		big[i] = 'x'
	}
	targetBig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(big)
	}))
	defer targetBig.Close()

	payloadBig, _ := json.Marshal(ProxyRequest{URL: targetBig.URL, Method: "GET"})
	reqBig, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payloadBig))
	reqBig.Header.Set("X-EF-Token", "tok")
	respBig, err := http.DefaultClient.Do(reqBig)
	if err != nil {
		t.Fatalf("big proxy request failed: %v", err)
	}
	var bigData map[string]interface{}
	json.NewDecoder(respBig.Body).Decode(&bigData)
	respBig.Body.Close()
	if respBig.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected 502 for oversized proxied response, got %d", respBig.StatusCode)
	}
	if bigData["error"] == nil || !strings.Contains(bigData["error"].(string), "too large") {
		t.Errorf("Expected 'too large' error message, got %v", bigData["error"])
	}

	// 2. Redirects must NOT be followed: the raw 302 is surfaced back
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("final destination"))
	}))
	defer redirectTarget.Close()

	targetRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer targetRedirect.Close()

	payloadRedir, _ := json.Marshal(ProxyRequest{URL: targetRedirect.URL, Method: "GET"})
	reqRedir, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payloadRedir))
	reqRedir.Header.Set("X-EF-Token", "tok")
	respRedir, err := http.DefaultClient.Do(reqRedir)
	if err != nil {
		t.Fatalf("redirect proxy request failed: %v", err)
	}
	var redirData map[string]interface{}
	json.NewDecoder(respRedir.Body).Decode(&redirData)
	respRedir.Body.Close()
	if redirData["statusCode"].(float64) != float64(http.StatusFound) {
		t.Errorf("Expected raw 302 to be returned (not followed), got %v", redirData["statusCode"])
	}
}

func TestHealthEndpointDoesNotExposeToken(t *testing.T) {
	agent := NewAgentServer("super-secret-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
	if err != nil {
		t.Fatalf("Failed to create health request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}
	if tokenVal, ok := data["token"]; ok && tokenVal != "" {
		t.Errorf("Health endpoint should not expose token, got %v", tokenVal)
	}
}

func TestParseProcessList(t *testing.T) {
	psSample := "  PID USER      %CPU %MEM COMMAND\n" +
		"  375 jinhan    0.0  0.1 /Applications/Safari.app/Contents/MacOS/Safari\n" +
		"    1 root      0.0  0.0 /sbin/launchd\n"
	items := parseProcessList(psSample, "darwin")
	if len(items) != 2 {
		t.Fatalf("Expected 2 processes from ps output, got %d (%+v)", len(items), items)
	}
	if items[0].PID != "375" {
		t.Errorf("Expected PID 375, got %q", items[0].PID)
	}
	if items[0].Name != "/Applications/Safari.app/Contents/MacOS/Safari" {
		t.Errorf("Expected full command as name, got %q", items[0].Name)
	}

	csvSample := "\"chrome.exe\",\"1234\",\"Console\",\"1\",\"120,000 K\"\n" +
		"\"explorer.exe\",\"5678\",\"Console\",\"1\",\"80,000 K\"\n"
	winItems := parseProcessList(csvSample, "windows")
	if len(winItems) != 2 {
		t.Fatalf("Expected 2 processes from tasklist CSV, got %d (%+v)", len(winItems), winItems)
	}
	if winItems[0].PID != "1234" || winItems[0].Name != "chrome.exe" || winItems[0].Memory != "120,000 K" {
		t.Errorf("Unexpected windows process: %+v", winItems[0])
	}

	// Garbage input yields empty slice, never a panic
	if got := parseProcessList("", "darwin"); len(got) != 0 {
		t.Errorf("Expected empty result for empty input, got %+v", got)
	}
}

func TestVersionIsInjectable(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "9.9.9-test"

	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	if data["version"] != "9.9.9-test" {
		t.Errorf("Expected injected version 9.9.9-test, got %v", data["version"])
	}
}

func TestProxyRequestBodyLimit(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	agent.MaxRequestBodyBytes = 256
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	oversizedPayload := fmt.Sprintf(`{"url":"http://127.0.0.1:8080","method":"POST","body":"%s"}`, strings.Repeat("A", 512))
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", strings.NewReader(oversizedPayload))
	req.Header.Set("X-EF-Token", "test-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413, got %d", resp.StatusCode)
	}
}

func TestHealthEndpointAuthenticatedField(t *testing.T) {
	agent := NewAgentServer("test-token-1234", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	// 1. Without token -> authenticated: false
	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	defer resp1.Body.Close()
	var data1 map[string]interface{}
	json.NewDecoder(resp1.Body).Decode(&data1)
	if data1["authenticated"] != false {
		t.Fatalf("expected authenticated=false without token, got %v", data1["authenticated"])
	}

	// 2. With wrong token -> authenticated: false
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
	req2.Header.Set("X-EF-Token", "wrong-token")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	defer resp2.Body.Close()
	var data2 map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&data2)
	if data2["authenticated"] != false {
		t.Fatalf("expected authenticated=false with wrong token, got %v", data2["authenticated"])
	}

	// 3. With valid token -> authenticated: true
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/health", nil)
	req3.Header.Set("X-EF-Token", "test-token-1234")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("request 3 failed: %v", err)
	}
	defer resp3.Body.Close()
	var data3 map[string]interface{}
	json.NewDecoder(resp3.Body).Decode(&data3)
	if data3["authenticated"] != true {
		t.Fatalf("expected authenticated=true with valid token, got %v", data3["authenticated"])
	}
}
