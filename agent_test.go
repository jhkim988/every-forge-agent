package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

		// Fallback origin for non-whitelisted external domain
		reqOther, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/health", nil)
		reqOther.Header.Set("Origin", "https://external-domain.com")
		respOther, _ := http.DefaultClient.Do(reqOther)
		defer respOther.Body.Close()
		if respOther.Header.Get("Access-Control-Allow-Origin") != "https://every-forge.com" {
			t.Errorf("Expected fallback origin https://every-forge.com, got %s", respOther.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("Authentication Guard", func(t *testing.T) {
		// 1. Missing token
		req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		resp1, _ := http.DefaultClient.Do(req1)
		defer resp1.Body.Close()
		if resp1.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for missing token, got %d", resp1.StatusCode)
		}

		// 2. Invalid X-EF-Token
		req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req2.Header.Set("X-EF-Token", "wrong-token-abc")
		resp2, _ := http.DefaultClient.Do(req2)
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized for invalid X-EF-Token, got %d", resp2.StatusCode)
		}

		// 3. Valid X-EF-Token
		req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req3.Header.Set("X-EF-Token", "test-secret-token")
		resp3, _ := http.DefaultClient.Do(req3)
		defer resp3.Body.Close()
		if resp3.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK for valid X-EF-Token, got %d", resp3.StatusCode)
		}

		// 4. Valid Bearer Token in Authorization header
		req4, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req4.Header.Set("Authorization", "Bearer test-secret-token")
		resp4, _ := http.DefaultClient.Do(req4)
		defer resp4.Body.Close()
		if resp4.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK for valid Bearer token, got %d", resp4.StatusCode)
		}

		// 5. Invalid Bearer Token in Authorization header
		req5, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/process/list", nil)
		req5.Header.Set("Authorization", "Bearer invalid-token")
		resp5, _ := http.DefaultClient.Do(req5)
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
		respGet, _ := http.DefaultClient.Do(reqGet)
		defer respGet.Body.Close()
		if respGet.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 Method Not Allowed for GET /api/proxy, got %d", respGet.StatusCode)
		}

		// 3. Proxy request with invalid JSON payload
		reqBadJson, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader([]byte("{invalid-json")))
		reqBadJson.Header.Set("Content-Type", "application/json")
		reqBadJson.Header.Set("X-EF-Token", "test-secret-token")
		respBadJson, _ := http.DefaultClient.Do(reqBadJson)
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
		respUnreach, _ := http.DefaultClient.Do(reqUnreach)
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
		respKillNoPid, _ := http.DefaultClient.Do(reqKillNoPid)
		defer respKillNoPid.Body.Close()
		if respKillNoPid.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for missing pid, got %d", respKillNoPid.StatusCode)
		}

		// Process Kill: Invalid PID execution handles error cleanly
		reqKillInvalid, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/process/kill?pid=99999999", nil)
		reqKillInvalid.Header.Set("X-EF-Token", "test-secret-token")
		respKillInvalid, _ := http.DefaultClient.Do(reqKillInvalid)
		defer respKillInvalid.Body.Close()
		// Non-existent PID returns 500 error on OS taskkill/kill failure
		if respKillInvalid.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected 500 for non-existent PID kill, got %d", respKillInvalid.StatusCode)
		}
	})
}
