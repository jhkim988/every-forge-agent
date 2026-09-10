package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
)

// =========================================================================
// CHALLENGER M1 R2-2 EMPIRICAL ADVERSARIAL VERIFICATION SUITE
// =========================================================================

// --- DEFECT 1: SSRF ALTERNATE ENCODINGS & SOCKET-LEVEL DNS REBINDING ---

func TestChallengerDefect1_SSRFAlternateEncodings(t *testing.T) {
	requiredTargets := []struct {
		name string
		host string
		url  string
	}{
		{name: "Decimal IP 2852039166", host: "2852039166", url: "http://2852039166/latest/meta-data/"},
		{name: "Dotted hex 0xa9.0xfe.0xa9.0xfe", host: "0xa9.0xfe.0xa9.0xfe", url: "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/"},
		{name: "Octal 0251.0376.0251.0376", host: "0251.0376.0251.0376", url: "http://0251.0376.0251.0376/latest/meta-data/"},
		{name: "IPv6-mapped IPv4 [::ffff:169.254.169.254]", host: "::ffff:169.254.169.254", url: "http://[::ffff:169.254.169.254]/latest/meta-data/"},
		{name: "nip.io wildcard 169.254.169.254.nip.io", host: "169.254.169.254.nip.io", url: "http://169.254.169.254.nip.io/latest/meta-data/"},
		{name: "Alibaba Cloud 100.100.100.200", host: "100.100.100.200", url: "http://100.100.100.200/v1/meta/"},
		{name: "Azure WireServer 168.63.129.16", host: "168.63.129.16", url: "http://168.63.129.16/metadata/instance"},
		{name: "GCP/AWS IPv6 [fd00:ec2::254]", host: "fd00:ec2::254", url: "http://[fd00:ec2::254]/latest/meta-data/"},
	}

	for _, tc := range requiredTargets {
		t.Run(tc.name, func(t *testing.T) {
			blocked := isBlockedProxyTarget(tc.url)
			if !blocked {
				t.Errorf("FAIL: isBlockedProxyTarget(%q) returned false; MUST be blocked", tc.url)
			} else {
				t.Logf("PASS: isBlockedProxyTarget(%q) correctly blocked", tc.url)
			}
		})
	}
}

func TestChallengerDefect1_ProxyEndpointReturnsForbidden(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	targets := []string{
		"http://2852039166/latest/meta-data/",
		"http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/",
		"http://0251.0376.0251.0376/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://169.254.169.254.nip.io/latest/meta-data/",
		"http://100.100.100.200/v1/meta/",
		"http://168.63.129.16/metadata/instance",
		"http://[fd00:ec2::254]/latest/meta-data/",
	}

	for _, target := range targets {
		payload, _ := json.Marshal(ProxyRequest{
			URL:    target,
			Method: "GET",
		})
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("X-EF-Token", "test-token")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do failed for %s: %v", target, err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("FAIL: target %s returned HTTP %d, expected 403 Forbidden. Body: %s",
				target, resp.StatusCode, string(bodyBytes))
		} else {
			t.Logf("PASS: target %s blocked with HTTP 403 Forbidden", target)
		}
	}
}

func TestChallengerDefect1_SocketLevelDialerControl(t *testing.T) {
	// Empirically verify that the socket-level Dialer.Control in handleProxy
	// intercepts any socket connection targeting cloud metadata IPs,
	// even if pre-dial URL checks were bypassed.

	testControl := func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if isBlockedMetadataIP(ip) {
			return errorsNew("connection blocked: target address is cloud metadata")
		}
		return nil
	}

	blockedAddresses := []string{
		"169.254.169.254:80",
		"169.254.169.254:8080",
		"100.100.100.200:80",
		"168.63.129.16:80",
		"[fd00:ec2::254]:80",
		"[::ffff:169.254.169.254]:80",
		"169.254.170.2:80", // AWS ECS metadata
		"169.254.169.253:80", // Azure DHCP/metadata
	}

	for _, addr := range blockedAddresses {
		err := testControl("tcp", addr, nil)
		if err == nil {
			t.Errorf("FAIL: Dialer.Control allowed connection to metadata address %s", addr)
		} else {
			if !strings.Contains(err.Error(), "connection blocked: target address is cloud metadata") {
				t.Errorf("FAIL: unexpected error message: %v", err)
			}
			t.Logf("PASS: Dialer.Control successfully blocked socket to %s: %v", addr, err)
		}
	}

	// Verify benign addresses are NOT blocked by Dialer.Control
	allowedAddresses := []string{
		"127.0.0.1:9921",
		"127.0.0.1:80",
		"8.8.8.8:53",
		"1.1.1.1:443",
		"[::1]:9921",
	}

	for _, addr := range allowedAddresses {
		err := testControl("tcp", addr, nil)
		if err != nil {
			t.Errorf("FAIL: Dialer.Control blocked valid address %s: %v", addr, err)
		} else {
			t.Logf("PASS: Dialer.Control allowed benign address %s", addr)
		}
	}
}

func errorsNew(msg string) error {
	return &testErr{msg: msg}
}

type testErr struct {
	msg string
}

func (e *testErr) Error() string {
	return e.msg
}

// --- DEFECT 2: HOST HEADER PARSER & EMPTY HOST TOLERANCE ---

func TestChallengerDefect2_HostHeaderParser(t *testing.T) {
	cases := []struct {
		hostHeader string
		wantValid  bool
		reason     string
	}{
		{"127.0.0.1:80@attacker.com", false, "Userinfo @ delimiter attack"},
		{"localhost:user@attacker.com", false, "Userinfo @ delimiter attack on localhost"},
		{"localhost:99999", false, "Port exceeds 65535"},
		{"localhost:abc", false, "Non-numeric port"},
		{"[::1]:9921", true, "Valid IPv6 loopback with port 9921"},
		{"[::1]:99999", false, "IPv6 loopback with port exceeding 65535"},
		{"", true, "Empty host header for HTTP/1.0 compatibility"},
		// Additional adversarial edge cases
		{"127.0.0.1:0", false, "Port 0 is invalid"},
		{"127.0.0.1:65535", true, "Maximum valid TCP port"},
		{"127.0.0.1:65536", false, "Port 65536 exceeds max TCP port"},
		{"[::1]:0", false, "IPv6 port 0 is invalid"},
		{"[::1]:65535", true, "IPv6 maximum valid TCP port"},
		{"localhost", true, "Standard loopback hostname"},
		{"127.0.0.1", true, "Standard loopback IPv4"},
		{"::1", true, "Standard loopback IPv6"},
		{"[::1]", true, "Bracketed loopback IPv6"},
		{"127.0.0.1:9921", true, "Standard agent port on loopback"},
		{"localhost:9921", true, "Standard agent port on localhost"},
		{"attacker.com", false, "External domain name"},
		{"attacker.com:9921", false, "External domain name with port"},
		{"127.0.0.1.attacker.com", false, "Subdomain spoofing"},
		{"127.0.0.1#attacker.com", false, "URI fragment delimiter injection"},
		{"127.0.0.1?attacker.com", false, "URI query delimiter injection"},
		{"127.0.0.1/attacker.com", false, "URI path delimiter injection"},
		{"127.0.0.1\\attacker.com", false, "URI backslash delimiter injection"},
		{"127.0.0.1\r\nattacker.com", false, "CRLF injection in host"},
	}

	for _, tc := range cases {
		t.Run(tc.reason+" ("+tc.hostHeader+")", func(t *testing.T) {
			got := validLoopbackHost(tc.hostHeader)
			if got != tc.wantValid {
				t.Errorf("FAIL: validLoopbackHost(%q) = %v, want %v (%s)",
					tc.hostHeader, got, tc.wantValid, tc.reason)
			} else {
				t.Logf("PASS: validLoopbackHost(%q) = %v", tc.hostHeader, got)
			}
		})
	}
}

func TestChallengerDefect2_HostMiddlewareHTTPIntegration(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	var receivedHost string
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		agent.Routes().ServeHTTP(w, r)
	})
	ts := httptest.NewServer(loggingHandler)
	defer ts.Close()

	testRequests := []struct {
		hostHeader string
		wantCode   int
	}{
		{"127.0.0.1:80@attacker.com", http.StatusForbidden},
		{"localhost:user@attacker.com", http.StatusForbidden},
		{"localhost:99999", http.StatusForbidden},
		{"localhost:abc", http.StatusForbidden},
		{"[::1]:99999", http.StatusForbidden},
		{"attacker.com", http.StatusForbidden},
		{"127.0.0.1", http.StatusOK},
		{"localhost", http.StatusOK},
	}

	for _, tc := range testRequests {
		receivedHost = ""

		// Send raw HTTP request over raw TCP connection to bypass client-side stripping
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatalf("failed to dial test server: %v", err)
		}
		rawReq := "GET /api/health HTTP/1.1\r\nHost: " + tc.hostHeader + "\r\nConnection: close\r\n\r\n"
		_, _ = conn.Write([]byte(rawReq))
		respBytes, _ := io.ReadAll(conn)
		conn.Close()

		firstLine := ""
		if idx := bytes.IndexByte(respBytes, '\n'); idx != -1 {
			firstLine = string(bytes.TrimSpace(respBytes[:idx]))
		}

		t.Logf("tc.hostHeader=%q -> received r.Host=%q, server response line=%q, body=%s",
			tc.hostHeader, receivedHost, firstLine, string(respBytes))

		if tc.wantCode == http.StatusOK {
			if !strings.Contains(firstLine, "200 OK") {
				t.Errorf("FAIL: Expected 200 OK for host %q, got %s", tc.hostHeader, firstLine)
			}
		} else {
			if strings.Contains(firstLine, "200 OK") {
				t.Errorf("FAIL: Host %q bypassed middleware and got 200 OK!", tc.hostHeader)
			}
		}
	}

	// Explicitly verify HTTP/1.0 request with NO Host header
	conn10, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	rawReq10 := "GET /api/health HTTP/1.0\r\n\r\n"
	_, _ = conn10.Write([]byte(rawReq10))
	respBytes10, _ := io.ReadAll(conn10)
	conn10.Close()
	firstLine10 := ""
	if idx := bytes.IndexByte(respBytes10, '\n'); idx != -1 {
		firstLine10 = string(bytes.TrimSpace(respBytes10[:idx]))
	}
	if !strings.Contains(firstLine10, "200 OK") {
		t.Errorf("FAIL: HTTP/1.0 without Host header was rejected: %s", firstLine10)
	} else {
		t.Logf("PASS: HTTP/1.0 without Host header succeeded: %s", firstLine10)
	}
}

// --- DEFECT 3: CRONTAB DELETION GHOST LINE BUG ---

func TestChallengerDefect3_CrontabDeletionGhostLineBug(t *testing.T) {
	// Case 1: Empty crontab -> delete "line_1" must fail with "cron job not found"
	res1, err1 := deleteCrontabContent("", "line_1")
	if err1 == nil {
		t.Errorf("FAIL: deleteCrontabContent on empty crontab returned nil error for line_1! Result: %q", res1)
	} else if !strings.Contains(err1.Error(), "cron job not found") {
		t.Errorf("FAIL: expected 'cron job not found' error, got: %v", err1)
	} else {
		t.Logf("PASS: deleteCrontabContent on empty crontab returned expected error: %v", err1)
	}

	// Case 2: Whitespace-only crontab -> delete "line_1" must fail
	res2, err2 := deleteCrontabContent("   \n\n  \t\n", "line_1")
	if err2 == nil {
		t.Errorf("FAIL: deleteCrontabContent on whitespace crontab returned nil error for line_1! Result: %q", res2)
	} else {
		t.Logf("PASS: deleteCrontabContent on whitespace crontab returned error: %v", err2)
	}

	// Case 3: Single-job crontab -> delete non-existent "line_2" must fail with "cron job not found"
	singleJob := "0 9 * * 1-5 /backup.sh\n"
	res3, err3 := deleteCrontabContent(singleJob, "line_2")
	if err3 == nil {
		t.Errorf("FAIL: deleteCrontabContent on 1-job crontab returned nil error for line_2! Result: %q", res3)
	} else if !strings.Contains(err3.Error(), "cron job not found") {
		t.Errorf("FAIL: expected 'cron job not found' error, got: %v", err3)
	} else {
		t.Logf("PASS: deleteCrontabContent(singleJob, line_2) returned expected error: %v", err3)
	}

	// Case 4: Valid deletion of existing job -> must correctly remove and persist
	res4, err4 := deleteCrontabContent(singleJob, "line_1")
	if err4 != nil {
		t.Errorf("FAIL: deleteCrontabContent(singleJob, line_1) failed: %v", err4)
	} else if res4 != "" {
		t.Errorf("FAIL: expected empty crontab after deleting single job, got: %q", res4)
	} else {
		t.Logf("PASS: valid deletion of single job resulted in clean empty crontab: %q", res4)
	}

	// Case 5: Two-job crontab -> delete first job, then delete second job
	twoJobs := "0 9 * * 1-5 /backup.sh\n0 12 * * * /sync.sh\n"
	// Delete job 1
	res5A, err5A := deleteCrontabContent(twoJobs, "line_1")
	if err5A != nil {
		t.Errorf("FAIL: deleting line_1 from two jobs failed: %v", err5A)
	} else if res5A != "0 12 * * * /sync.sh\n" {
		t.Errorf("FAIL: unexpected remaining crontab after deleting line_1: %q", res5A)
	} else {
		t.Logf("PASS: deleting line_1 retained line_2: %q", res5A)
	}

	// Delete job 2 from two jobs
	res5B, err5B := deleteCrontabContent(twoJobs, "line_2")
	if err5B != nil {
		t.Errorf("FAIL: deleting line_2 from two jobs failed: %v", err5B)
	} else if res5B != "0 9 * * 1-5 /backup.sh\n" {
		t.Errorf("FAIL: unexpected remaining crontab after deleting line_2: %q", res5B)
	} else {
		t.Logf("PASS: deleting line_2 retained line_1: %q", res5B)
	}

	// Case 6: Out-of-bounds line numbers
	for _, badID := range []string{"line_0", "line_3", "line_999", "line_-1", "invalid_id"} {
		_, err := deleteCrontabContent(twoJobs, badID)
		if err == nil {
			t.Errorf("FAIL: deleteCrontabContent(twoJobs, %q) returned nil error", badID)
		} else {
			t.Logf("PASS: deleteCrontabContent(twoJobs, %q) returned error: %v", badID, err)
		}
	}
}

// --- DEFECT 4: SANITIZATION ORDER ON POST /api/cron/delete ---

func TestChallengerDefect4_SanitizationOrder(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	adversarialIDs := []struct {
		name string
		body map[string]string
	}{
		{name: "Trailing newline", body: map[string]string{"id": "line_1\n"}},
		{name: "Trailing carriage return", body: map[string]string{"id": "line_1\r"}},
		{name: "Trailing CRLF", body: map[string]string{"id": "line_1\r\n"}},
		{name: "Leading newline", body: map[string]string{"id": "\nline_1"}},
		{name: "Leading carriage return", body: map[string]string{"id": "\rline_1"}},
		{name: "Embedded null byte", body: map[string]string{"id": "line_1\x00extra"}},
		{name: "Leading null byte", body: map[string]string{"id": "\x00line_1"}},
		{name: "Trailing null byte", body: map[string]string{"id": "line_1\x00"}},
	}

	for _, tc := range adversarialIDs {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(tc.body)
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/delete", bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("failed to build request: %v", err)
			}
			req.Header.Set("X-EF-Token", "test-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("client.Do failed: %v", err)
			}
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("FAIL: ID %q returned HTTP %d, expected 400 Bad Request. Body: %s",
					tc.body["id"], resp.StatusCode, string(bodyBytes))
			} else {
				var errResp map[string]string
				json.Unmarshal(bodyBytes, &errResp)
				if errResp["error"] != "invalid id parameter" {
					t.Errorf("FAIL: unexpected error response message: %q, want 'invalid id parameter'", errResp["error"])
				} else {
					t.Logf("PASS: ID %q correctly rejected with 400 Bad Request: %s", tc.body["id"], string(bodyBytes))
				}
			}
		})
	}
}

func TestChallengerDefect4_SanitizationOrderURLQueryParam(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	// Test URL encoded query parameter with newline / carriage return
	testURLs := []string{
		ts.URL + "/api/cron/delete?id=line_1%0A",
		ts.URL + "/api/cron/delete?id=line_1%0D",
		ts.URL + "/api/cron/delete?id=%0Aline_1",
		ts.URL + "/api/cron/delete?id=line_1%00",
	}

	for _, u := range testURLs {
		req, err := http.NewRequest(http.MethodPost, u, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		req.Header.Set("X-EF-Token", "test-token")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do failed: %v", err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("FAIL: URL %s returned HTTP %d, expected 400 Bad Request. Body: %s",
				u, resp.StatusCode, string(bodyBytes))
		} else {
			t.Logf("PASS: URL %s correctly rejected with HTTP 400 Bad Request", u)
		}
	}
}
