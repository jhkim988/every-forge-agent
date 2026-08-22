package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEchoServer(t *testing.T) {
	ts := httptest.NewServer(EchoRouter())
	defer ts.Close()

	t.Run("Permissive CORS Headers & OPTIONS Preflight", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/echo", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("OPTIONS request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("Expected 204 No Content for OPTIONS, got %d", resp.StatusCode)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("Expected CORS origin '*', got %s", resp.Header.Get("Access-Control-Allow-Origin"))
		}
		if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "GET") ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "POST") {
			t.Errorf("Expected complete CORS methods, got %s", resp.Header.Get("Access-Control-Allow-Methods"))
		}
	})

	t.Run("Router Endpoints (/, /echo, /api/echo)", func(t *testing.T) {
		endpoints := []string{"/", "/echo", "/api/echo"}
		for _, ep := range endpoints {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+ep, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET %s failed: %v", ep, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected 200 for %s, got %d", ep, resp.StatusCode)
			}

			var data EchoResponse
			json.NewDecoder(resp.Body).Decode(&data)
			if data.Method != "GET" {
				t.Errorf("Expected method GET for %s, got %s", ep, data.Method)
			}
			if data.Path != ep {
				t.Errorf("Expected path %s, got %s", ep, data.Path)
			}
		}
	})

	t.Run("Echo GET with Query Parameters and Custom Headers", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/echo?foo=bar&count=42&filter=active", nil)
		req.Header.Set("X-Custom-Header", "Every-Forge-Studio")
		req.Header.Set("User-Agent", "EveryForgeClient/2.0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Echo GET failed: %v", err)
		}
		defer resp.Body.Close()

		var data EchoResponse
		json.NewDecoder(resp.Body).Decode(&data)

		if data.Method != "GET" {
			t.Errorf("Expected GET, got %v", data.Method)
		}
		if data.Headers["X-Custom-Header"] != "Every-Forge-Studio" {
			t.Errorf("Expected custom header, got %v", data.Headers["X-Custom-Header"])
		}
		if data.Query["foo"] != "bar" || data.Query["count"] != "42" || data.Query["filter"] != "active" {
			t.Errorf("Unexpected query mapping: %v", data.Query)
		}
		if data.Timestamp <= 0 {
			t.Errorf("Expected positive unix millisecond timestamp, got %d", data.Timestamp)
		}
	})

	t.Run("Echo POST with JSON Payload", func(t *testing.T) {
		bodyPayload := `{"name":"Every-Forge","version":"2.0.0","active":true}`
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/echo", bytes.NewReader([]byte(bodyPayload)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Echo POST failed: %v", err)
		}
		defer resp.Body.Close()

		var data EchoResponse
		json.NewDecoder(resp.Body).Decode(&data)

		if data.Method != "POST" {
			t.Errorf("Expected POST, got %v", data.Method)
		}
		if data.Body != bodyPayload {
			t.Errorf("Expected raw body matched, got %v", data.Body)
		}
		if data.Headers["Content-Type"] != "application/json" {
			t.Errorf("Expected Content-Type header preserved, got %v", data.Headers["Content-Type"])
		}
	})

	t.Run("Echo PUT, DELETE, PATCH Methods", func(t *testing.T) {
		methods := []struct {
			method string
			body   string
		}{
			{method: http.MethodPut, body: `{"status":"updated"}`},
			{method: http.MethodDelete, body: ""},
			{method: http.MethodPatch, body: `{"partial":"change"}`},
		}

		for _, m := range methods {
			var bodyReader *bytes.Reader
			if m.body != "" {
				bodyReader = bytes.NewReader([]byte(m.body))
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}

			req, _ := http.NewRequest(m.method, ts.URL+"/echo?action="+m.method, bodyReader)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Request %s failed: %v", m.method, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected 200 for %s, got %d", m.method, resp.StatusCode)
			}

			var data EchoResponse
			json.NewDecoder(resp.Body).Decode(&data)
			if data.Method != m.method {
				t.Errorf("Expected method %s, got %s", m.method, data.Method)
			}
			if m.body != "" && data.Body != m.body {
				t.Errorf("Expected body %s, got %s", m.body, data.Body)
			}
			if data.Query["action"] != m.method {
				t.Errorf("Expected query action=%s, got %s", m.method, data.Query["action"])
			}
		}
	})
}
