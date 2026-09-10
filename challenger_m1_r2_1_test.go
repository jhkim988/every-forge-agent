package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// CHALLENGER M1 R2-1: EMPIRICAL ADVERSARIAL VERIFICATION SUITE
// Process & Port Correlation & Safe Process Kill
// =============================================================================

// --- 1. Port Correlation & Edge Cases: non-numeric, malformed, IPv6, dedup ---

func TestChallenger_PortCorrelation_EdgeCases(t *testing.T) {
	t.Run("ParseLsofOutput_AdversarialEdgeCases", func(t *testing.T) {
		sampleLsof := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Antigravi   107 jinhan   34u  IPv4 0x33ffa09eacfa6a60      0t0  TCP 127.0.0.1:53148 (LISTEN)
Antigravi   107 jinhan   37u  IPv4 0x62a882081fcb88c5      0t0  TCP 127.0.0.1:53152 (LISTEN)
Antigravi   107 jinhan   38u  IPv6 0x62a882081fcb88c6      0t0  TCP [::1]:53148 (LISTEN)
Antigravi   107 jinhan   39u  IPv6 0x62a882081fcb88c7      0t0  TCP *:53148 (LISTEN)
badproc     201 jinhan   10u  IPv4 0x1111111111111111      0t0  TCP 127.0.0.1:0 (LISTEN)
badproc     202 jinhan   11u  IPv4 0x2222222222222222      0t0  TCP 127.0.0.1:65536 (LISTEN)
badproc     203 jinhan   12u  IPv4 0x3333333333333333      0t0  TCP 127.0.0.1:-80 (LISTEN)
badproc     204 jinhan   13u  IPv4 0x4444444444444444      0t0  TCP 127.0.0.1:http (LISTEN)
badproc     205 jinhan   14u  IPv4 0x5555555555555555      0t0  TCP 127.0.0.1:* (LISTEN)
badproc     206 jinhan   15u  IPv4 0x6666666666666666      0t0  TCP 127.0.0.1 (LISTEN)
badpid      abc jinhan   16u  IPv4 0x7777777777777777      0t0  TCP 127.0.0.1:8080 (LISTEN)
truncated_line_no_fields
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
scopeproc   301 jinhan   17u  IPv6 0x8888888888888888      0t0  TCP [fe80::1%lo0]:8080 (LISTEN)
scopeproc   301 jinhan   18u  IPv6 0x9999999999999999      0t0  TCP [2001:db8::1]:8080 (LISTEN)
boundary    401 jinhan   19u  IPv4 0xaaaaaaaaaaaaaaaa      0t0  TCP 0.0.0.0:1 (LISTEN)
boundary    401 jinhan   20u  IPv4 0xbbbbbbbbbbbbbbbb      0t0  TCP 0.0.0.0:65535 (LISTEN)
`
		portMap := make(map[string][]string)
		parseLsofOutput(sampleLsof, portMap)
		sortPortMap(portMap)

		// 1. Port Deduplication: PID 107 has 53148 repeated across 127.0.0.1, [::1], and *
		expected107 := []string{"tcp/53148", "tcp/53152"}
		if !reflect.DeepEqual(portMap["107"], expected107) {
			t.Errorf("FAIL: PID 107 deduplication/sorting got %v, want %v", portMap["107"], expected107)
		} else {
			t.Logf("PASS: PID 107 deduplication correctly produced %v", portMap["107"])
		}

		// 2. Non-numeric & Invalid Port Rejection (0, 65536, -80, http, *, no port)
		invalidPIDs := []string{"201", "202", "203", "204", "205", "206", "abc"}
		for _, pid := range invalidPIDs {
			if ports, ok := portMap[pid]; ok {
				t.Errorf("FAIL: Malformed/invalid PID %s unexpectedly included in portMap: %v", pid, ports)
			}
		}

		// 3. IPv6 scoped and global address formatting
		expected301 := []string{"tcp/8080"}
		if !reflect.DeepEqual(portMap["301"], expected301) {
			t.Errorf("FAIL: IPv6 scoped PID 301 got %v, want %v", portMap["301"], expected301)
		} else {
			t.Logf("PASS: IPv6 scoped PID 301 correctly parsed port: %v", portMap["301"])
		}

		// 4. Boundary ports 1 and 65535
		expected401 := []string{"tcp/1", "tcp/65535"}
		if !reflect.DeepEqual(portMap["401"], expected401) {
			t.Errorf("FAIL: Boundary ports PID 401 got %v, want %v", portMap["401"], expected401)
		} else {
			t.Logf("PASS: Boundary ports PID 401 parsed correctly: %v", portMap["401"])
		}
	})

	t.Run("ParseSsOutput_AdversarialEdgeCases", func(t *testing.T) {
		sampleSs := `Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:80          0.0.0.0:*         users:(("nginx",pid=701,fd=6),("nginx",pid=702,fd=6))
tcp   LISTEN 0      128    [::]:80             [::]:*            users:(("nginx",pid=701,fd=7),("nginx",pid=702,fd=7))
tcp   LISTEN 0      511    :::443              :::*              users:(("envoy",pid=800,fd=10))
tcp   LISTEN 0      128    [::1]:443           [::]:*            users:(("envoy",pid=800,fd=11))
tcp   LISTEN 0      128    127.0.0.1:invalid   0.0.0.0:*         users:(("bad1",pid=901,fd=1))
tcp   LISTEN 0      128    127.0.0.1:0         0.0.0.0:*         users:(("bad2",pid=902,fd=1))
tcp   LISTEN 0      128    127.0.0.1:70000     0.0.0.0:*         users:(("bad3",pid=903,fd=1))
tcp   LISTEN 0      128    127.0.0.1:*         0.0.0.0:*         users:(("bad4",pid=904,fd=1))
tcp   LISTEN 0      128    127.0.0.1           0.0.0.0:*         users:(("bad5",pid=905,fd=1))
tcp   LISTEN 0      128    127.0.0.1:8080      0.0.0.0:*         users:(("nopid"))
tcp   ESTAB  0      0      127.0.0.1:54321     127.0.0.1:80      users:(("curl",pid=999,fd=3))
`
		portMap := make(map[string][]string)
		parseSsOutput(sampleSs, portMap)
		sortPortMap(portMap)

		// 1. Socket sharing between multiple PIDs (nginx master/worker)
		if !reflect.DeepEqual(portMap["701"], []string{"tcp/80"}) {
			t.Errorf("FAIL: ss PID 701 got %v, want [tcp/80]", portMap["701"])
		}
		if !reflect.DeepEqual(portMap["702"], []string{"tcp/80"}) {
			t.Errorf("FAIL: ss PID 702 got %v, want [tcp/80]", portMap["702"])
		}

		// 2. Deduplication across :::443 and [::1]:443
		if !reflect.DeepEqual(portMap["800"], []string{"tcp/443"}) {
			t.Errorf("FAIL: ss PID 800 dedup got %v, want [tcp/443]", portMap["800"])
		} else {
			t.Logf("PASS: ss PID 800 deduplication confirmed: %v", portMap["800"])
		}

		// 3. Rejection of invalid ports and non-LISTEN states
		invalidPIDs := []string{"901", "902", "903", "904", "905", "999"}
		for _, pid := range invalidPIDs {
			if ports, ok := portMap[pid]; ok {
				t.Errorf("FAIL: ss invalid PID %s unexpectedly included in portMap: %v", pid, ports)
			}
		}
	})

	t.Run("Live_getListeningPortsByPID_Execution", func(t *testing.T) {
		portMap := getListeningPortsByPID(runtime.GOOS)
		if len(portMap) == 0 {
			t.Logf("WARNING: getListeningPortsByPID returned empty map on %s (could happen if no listening ports)", runtime.GOOS)
		} else {
			t.Logf("PASS: getListeningPortsByPID returned %d listening processes on %s", len(portMap), runtime.GOOS)
			for pid, ports := range portMap {
				// Verify all ports are formatted as tcp/<int>
				for _, p := range ports {
					if !strings.HasPrefix(p, "tcp/") {
						t.Errorf("FAIL: Port tag %q does not have tcp/ prefix for PID %s", p, pid)
					}
					num := extractPortNumber(p)
					if num <= 0 || num > 65535 {
						t.Errorf("FAIL: Port tag %q contains invalid numeric port %d for PID %s", p, num, pid)
					}
				}
				// Verify sorting
				for i := 1; i < len(ports); i++ {
					if extractPortNumber(ports[i-1]) > extractPortNumber(ports[i]) {
						t.Errorf("FAIL: Ports for PID %s not sorted numerically: %v", pid, ports)
					}
				}
				// Break after checking first 5 for brevity
				break
			}
		}
	})
}

// --- 2. handleProcessKill Security Requirements ---

func TestChallenger_HandleProcessKill_Security(t *testing.T) {
	token := "challenger-secret-token-xyz"
	agent := NewAgentServer(token, false)
	handler := agent.Routes()

	// 2.1 GET / HEAD / PUT requests must return 405 Method Not Allowed
	t.Run("HTTP_Method_Restriction_Returns_405", func(t *testing.T) {
		disallowedMethods := []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
		}

		for _, method := range disallowedMethods {
			req := httptest.NewRequest(method, "/api/process/kill", bytes.NewBufferString(`{"pid": 1234}`))
			req.Host = "127.0.0.1:9921"
			req.Header.Set("X-EF-Token", token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("FAIL: Method %s expected 405 Method Not Allowed, got %d. Body: %s",
					method, w.Code, w.Body.String())
			}
			if w.Header().Get("Allow") != "POST" {
				t.Errorf("FAIL: Method %s expected 'Allow: POST' header, got %q",
					method, w.Header().Get("Allow"))
			}
			t.Logf("PASS: Method %s returned 405 Method Not Allowed with Allow: POST", method)
		}
	})

	// 2.2 Unauthenticated requests must return 401 Unauthorized
	t.Run("Unauthenticated_Requests_Return_401", func(t *testing.T) {
		unauthCases := []struct {
			name   string
			method string
			token  string
		}{
			{"Missing token on POST", http.MethodPost, ""},
			{"Wrong token on POST", http.MethodPost, "wrong-token"},
			{"Missing token on GET", http.MethodGet, ""},
			{"Wrong token on GET", http.MethodGet, "invalid-token"},
			{"Missing token on PUT", http.MethodPut, ""},
		}

		for _, tc := range unauthCases {
			req := httptest.NewRequest(tc.method, "/api/process/kill", bytes.NewBufferString(`{"pid": 1234}`))
			req.Host = "127.0.0.1:9921"
			if tc.token != "" {
				req.Header.Set("X-EF-Token", tc.token)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("FAIL: Case %s expected 401 Unauthorized, got %d. Body: %s",
					tc.name, w.Code, w.Body.String())
			}
			t.Logf("PASS: %s correctly returned 401 Unauthorized", tc.name)
		}
	})

	// 2.3 Non-numeric PID or negative PID must return 400 Bad Request
	t.Run("NonNumeric_And_Negative_PID_Returns_400", func(t *testing.T) {
		invalidPIDs := []struct {
			name    string
			payload string
		}{
			{"Non-numeric alpha string", `{"pid": "kill_it"}`},
			{"Non-numeric special chars", `{"pid": "1234; reboot"}`},
			{"Shell pipe injection", `{"pid": "1234 | rm -rf /"}`},
			{"Negative integer -1 (broadcast kill)", `{"pid": -1}`},
			{"Negative string '-1'", `{"pid": "-1"}`},
			{"Negative integer -999", `{"pid": -999}`},
			{"Negative string '-999'", `{"pid": "-999"}`},
			{"Zero integer 0", `{"pid": 0}`},
			{"Zero string '0'", `{"pid": "0"}`},
			{"Exceeding macOS pid_max (4194305)", `{"pid": 4194305}`},
			{"Huge overflow PID", `{"pid": 999999999999}`},
			{"Boolean PID true", `{"pid": true}`},
			{"Array PID [1234]", `{"pid": [1234]}`},
			{"Object PID", `{"pid": {"target": 1234}}`},
			{"Null PID", `{"pid": null}`},
			{"Missing PID key", `{}`},
		}

		for _, tc := range invalidPIDs {
			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(tc.payload))
			req.Host = "127.0.0.1:9921"
			req.Header.Set("X-EF-Token", token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("FAIL: %s expected 400 Bad Request, got %d. Body: %s",
					tc.name, w.Code, w.Body.String())
			}

			var resp ProcessKillResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("FAIL: Failed to decode JSON error response: %v", err)
			}
			if resp.Status != "error" {
				t.Errorf("FAIL: %s expected status 'error', got %q", tc.name, resp.Status)
			}
			t.Logf("PASS: %s rejected with 400 Bad Request: %s", tc.name, resp.Error)
		}
	})

	// 2.4 PID 1 (init) must be rejected with 400 Bad Request
	t.Run("PID_1_Init_Rejection_Returns_400", func(t *testing.T) {
		initCases := []struct {
			name    string
			payload string
		}{
			{"Init PID as integer 1", `{"pid": 1}`},
			{"Init PID as string '1'", `{"pid": "1"}`},
			{"Init PID via query parameter", ""},
		}

		for _, tc := range initCases {
			url := "/api/process/kill"
			var body *bytes.Buffer
			if tc.payload != "" {
				body = bytes.NewBufferString(tc.payload)
			} else {
				url += "?pid=1"
				body = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(http.MethodPost, url, body)
			req.Host = "127.0.0.1:9921"
			req.Header.Set("X-EF-Token", token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("FAIL: %s expected 400 Bad Request, got %d. Body: %s",
					tc.name, w.Code, w.Body.String())
			}

			var resp ProcessKillResponse
			_ = json.NewDecoder(w.Body).Decode(&resp)
			if !strings.Contains(resp.Error, "refusing to terminate system init (PID 1)") {
				t.Errorf("FAIL: %s expected init guard message, got %q", tc.name, resp.Error)
			} else {
				t.Logf("PASS: %s rejected with init guard: %s", tc.name, resp.Error)
			}
		}
	})

	// 2.5 Agent's own PID (self-kill) must be rejected with 400 Bad Request
	t.Run("Self_Agent_PID_Rejection_Returns_400", func(t *testing.T) {
		selfPID := os.Getpid()
		selfCases := []struct {
			name    string
			payload string
		}{
			{"Self PID as integer", fmt.Sprintf(`{"pid": %d}`, selfPID)},
			{"Self PID as string", fmt.Sprintf(`{"pid": "%d"}`, selfPID)},
			{"Self PID via query parameter", ""},
		}

		for _, tc := range selfCases {
			url := "/api/process/kill"
			var body *bytes.Buffer
			if tc.payload != "" {
				body = bytes.NewBufferString(tc.payload)
			} else {
				url += fmt.Sprintf("?pid=%d", selfPID)
				body = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(http.MethodPost, url, body)
			req.Host = "127.0.0.1:9921"
			req.Header.Set("X-EF-Token", token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("FAIL: %s expected 400 Bad Request, got %d. Body: %s",
					tc.name, w.Code, w.Body.String())
			}

			var resp ProcessKillResponse
			_ = json.NewDecoder(w.Body).Decode(&resp)
			if !strings.Contains(resp.Error, "refusing to terminate agent process itself") {
				t.Errorf("FAIL: %s expected self-termination guard message, got %q", tc.name, resp.Error)
			} else {
				t.Logf("PASS: %s rejected with self-termination guard: %s", tc.name, resp.Error)
			}
		}
	})

	// 2.6 Signal validation: SIGTERM (15) and SIGKILL (9) supported, invalid signals rejected
	t.Run("Signal_Validation_Supported_And_Rejected", func(t *testing.T) {
		// Valid signals must pass signal validation (we test on non-existent PID 4194300 so it fails at OS kill, not 400)
		validSignals := []struct {
			name string
			sig  string
		}{
			{"Default empty signal", ""},
			{"SIGTERM uppercase", "SIGTERM"},
			{"SIGTERM lowercase", "sigterm"},
			{"SIGTERM numeric 15", "15"},
			{"SIGKILL uppercase", "SIGKILL"},
			{"SIGKILL lowercase", "sigkill"},
			{"SIGKILL numeric 9", "9"},
		}

		for _, tc := range validSignals {
			payload := fmt.Sprintf(`{"pid": 4194300, "signal": %q}`, tc.sig)
			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
			req.Host = "127.0.0.1:9921"
			req.Header.Set("X-EF-Token", token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			var resp ProcessKillResponse
			_ = json.NewDecoder(w.Body).Decode(&resp)

			// Status must NOT be 400 with "unsupported signal"
			if w.Code == http.StatusBadRequest && strings.Contains(resp.Error, "unsupported signal") {
				t.Fatalf("FAIL: Valid signal %s (%q) was rejected as unsupported: %v", tc.name, tc.sig, resp.Error)
			}
			t.Logf("PASS: Valid signal %s (%q) accepted by signal validator (OS return %d)", tc.name, tc.sig, w.Code)
		}

		// Invalid signals must be strictly rejected with 400 Bad Request
		invalidSignals := []string{
			"SIGINT",
			"SIGSTOP",
			"SIGUSR1",
			"SIGHUP",
			"0",
			"-9",
			"-15",
			"SIGFOOBAR",
			"9; rm -rf /",
			"SIG\nKILL",
			"kill",
		}

		for _, sig := range invalidSignals {
			payload := fmt.Sprintf(`{"pid": 12345, "signal": %q}`, sig)
			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
			req.Host = "127.0.0.1:9921"
			req.Header.Set("X-EF-Token", token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("FAIL: Invalid signal %q expected 400 Bad Request, got %d. Body: %s",
					sig, w.Code, w.Body.String())
			}

			var resp ProcessKillResponse
			_ = json.NewDecoder(w.Body).Decode(&resp)
			if !strings.Contains(resp.Error, "unsupported signal") {
				t.Errorf("FAIL: Expected 'unsupported signal' error for %q, got %q", sig, resp.Error)
			} else {
				t.Logf("PASS: Invalid signal %q rejected with 400: %s", sig, resp.Error)
			}
		}
	})

	// 2.7 Live process termination of dummy child process with SIGTERM and SIGKILL
	t.Run("Live_Child_Process_Kill_Verification", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Skipping live process kill on Windows in CI environment")
		}

		// Test A: SIGTERM kills dummy process
		cmdA := exec.Command("sleep", "45")
		if err := cmdA.Start(); err != nil {
			t.Fatalf("FAIL: Failed to spawn dummy sleep process: %v", err)
		}
		pidA := strconv.Itoa(cmdA.Process.Pid)
		defer func() {
			_ = cmdA.Process.Kill()
			_ = cmdA.Wait()
		}()

		payloadA := fmt.Sprintf(`{"pid": "%s", "signal": "SIGTERM"}`, pidA)
		reqA := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payloadA))
		reqA.Host = "127.0.0.1:9921"
		reqA.Header.Set("X-EF-Token", token)
		reqA.Header.Set("Content-Type", "application/json")
		wA := httptest.NewRecorder()
		handler.ServeHTTP(wA, reqA)

		if wA.Code != http.StatusOK {
			t.Fatalf("FAIL: Live SIGTERM kill returned status %d: %s", wA.Code, wA.Body.String())
		}
		var respA ProcessKillResponse
		_ = json.NewDecoder(wA.Body).Decode(&respA)
		if respA.Status != "killed" || respA.PID != pidA || respA.Signal != "SIGTERM" {
			t.Fatalf("FAIL: Unexpected response for live SIGTERM: %+v", respA)
		}

		errA := cmdA.Wait()
		if errA == nil {
			t.Fatalf("FAIL: Process %s was expected to exit with signal termination, but exited cleanly", pidA)
		}
		t.Logf("PASS: Live dummy process %s successfully terminated with SIGTERM (exit: %v)", pidA, errA)

		// Test B: SIGKILL numeric '9' kills dummy process
		cmdB := exec.Command("sleep", "45")
		if err := cmdB.Start(); err != nil {
			t.Fatalf("FAIL: Failed to spawn dummy sleep process: %v", err)
		}
		pidB := strconv.Itoa(cmdB.Process.Pid)
		defer func() {
			_ = cmdB.Process.Kill()
			_ = cmdB.Wait()
		}()

		payloadB := fmt.Sprintf(`{"pid": %s, "signal": "9"}`, pidB)
		reqB := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payloadB))
		reqB.Host = "127.0.0.1:9921"
		reqB.Header.Set("X-EF-Token", token)
		reqB.Header.Set("Content-Type", "application/json")
		wB := httptest.NewRecorder()
		handler.ServeHTTP(wB, reqB)

		if wB.Code != http.StatusOK {
			t.Fatalf("FAIL: Live SIGKILL (9) kill returned status %d: %s", wB.Code, wB.Body.String())
		}
		var respB ProcessKillResponse
		_ = json.NewDecoder(wB.Body).Decode(&respB)
		if respB.Status != "killed" || respB.PID != pidB || respB.Signal != "SIGKILL" {
			t.Fatalf("FAIL: Unexpected response for live SIGKILL: %+v", respB)
		}

		errB := cmdB.Wait()
		if errB == nil {
			t.Fatalf("FAIL: Process %s was expected to exit with signal termination, but exited cleanly", pidB)
		}
		t.Logf("PASS: Live dummy process %s successfully terminated with SIGKILL numeric '9' (exit: %v)", pidB, errB)
	})
}
