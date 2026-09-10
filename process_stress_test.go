package main

import (
	"bytes"
	"context"
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
	"sync"
	"testing"
	"time"
)

// =============================================================================
// CHALLENGER M1-1: ADVERSARIAL STRESS TEST SUITE
// Process & Port Correlation & Safe Process Kill
// =============================================================================

// --- Section 1: Port Parsing Adversarial Inputs & Edge Cases ---

func TestStressParseLsofAdversarial(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name:     "Empty input",
			input:    "",
			expected: map[string][]string{},
		},
		{
			name:     "Whitespace only",
			input:    "   \n\t  \n  \r\n",
			expected: map[string][]string{},
		},
		{
			name: "Repeated headers and corrupt lines",
			input: `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
corrupt_line_without_enough_tokens
short line 1 2 3
`,
			expected: map[string][]string{},
		},
		{
			name: "IPv6 edge cases: [::1], [*], [fe80::1%lo0], and scoped addresses",
			input: `node       1001 user   12u  IPv6 0x1234 0t0 TCP [::1]:3000 (LISTEN)
node       1001 user   13u  IPv4 0x1235 0t0 TCP 127.0.0.1:3000 (LISTEN)
node       1001 user   14u  IPv6 0x1236 0t0 TCP *:3000 (LISTEN)
app        2002 user   15u  IPv6 0x1237 0t0 TCP [fe80::1%lo0]:8080 (LISTEN)
nginx      3003 user   16u  IPv6 0x1238 0t0 TCP [2001:db8::1]:443 (LISTEN)
`,
			expected: map[string][]string{
				"1001": {"tcp/3000"}, // Deduplicated across [::1], 127.0.0.1, and *
				"2002": {"tcp/8080"},
				"3003": {"tcp/443"},
			},
		},
		{
			name: "Boundary and invalid port numbers (0, negative, 65536, text)",
			input: `bad1       4001 user   10u  IPv4 0x1 0t0 TCP 127.0.0.1:0 (LISTEN)
bad2       4002 user   11u  IPv4 0x2 0t0 TCP 127.0.0.1:65536 (LISTEN)
bad3       4003 user   12u  IPv4 0x3 0t0 TCP 127.0.0.1:999999 (LISTEN)
bad4       4004 user   13u  IPv4 0x4 0t0 TCP 127.0.0.1:http (LISTEN)
bad5       4005 user   14u  IPv4 0x5 0t0 TCP 127.0.0.1:-80 (LISTEN)
good       4006 user   15u  IPv4 0x6 0t0 TCP 127.0.0.1:1 (LISTEN)
good       4006 user   16u  IPv4 0x7 0t0 TCP 127.0.0.1:65535 (LISTEN)
`,
			expected: map[string][]string{
				"4006": {"tcp/1", "tcp/65535"},
			},
		},
		{
			name: "Malformed PIDs (alpha, overflow, symbols)",
			input: `test       abc  user   10u  IPv4 0x1 0t0 TCP 127.0.0.1:80 (LISTEN)
test       12a  user   11u  IPv4 0x2 0t0 TCP 127.0.0.1:81 (LISTEN)
test       9999999999999999999999999 user 12u IPv4 0x3 0t0 TCP 127.0.0.1:82 (LISTEN)
`,
			expected: map[string][]string{},
		},
		{
			name: "Special characters and spaces in command name",
			input: `Google\x20Chrome 5001 user 10u IPv4 0x1 0t0 TCP 127.0.0.1:9222 (LISTEN)
Code\x20Helper   5002 user 11u IPv4 0x2 0t0 TCP 127.0.0.1:54321 (LISTEN)
My-App_v2.0      5003 user 12u IPv4 0x3 0t0 TCP 127.0.0.1:8000 (LISTEN)
`,
			expected: map[string][]string{
				"5001": {"tcp/9222"},
				"5002": {"tcp/54321"},
				"5003": {"tcp/8000"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			portMap := make(map[string][]string)
			parseLsofOutput(tc.input, portMap)
			sortPortMap(portMap)

			for pid, expectedPorts := range tc.expected {
				actualPorts, exists := portMap[pid]
				if !exists {
					t.Fatalf("Expected PID %s to exist in portMap, but not found", pid)
				}
				if !reflect.DeepEqual(actualPorts, expectedPorts) {
					t.Errorf("PID %s got %v, want %v", pid, actualPorts, expectedPorts)
				}
			}

			if len(portMap) != len(tc.expected) {
				t.Errorf("Expected %d PIDs in portMap, got %d: %v", len(tc.expected), len(portMap), portMap)
			}
		})
	}
}

// TestLsofNegativePIDCorrelationSafety verifies that if a malformed negative PID (e.g. -12)
// somehow enters parseLsofOutput, it does NOT correlate to real processes and cannot be killed.
func TestLsofNegativePIDCorrelationSafety(t *testing.T) {
	input := `test -12 user 10u IPv4 0x1 0t0 TCP 127.0.0.1:80 (LISTEN)`
	portMap := make(map[string][]string)
	parseLsofOutput(input, portMap)

	// Note: strconv.Atoi("-12") succeeds, so portMap contains "-12"
	if _, exists := portMap["-12"]; !exists {
		t.Logf("Negative PID was filtered out")
	} else {
		t.Logf("Negative PID entered portMap: %v", portMap["-12"])
	}

	// However, real OS processes always have positive PIDs:
	items := []ProcessItem{
		{PID: "1234", Name: "node"},
		{PID: "5678", Name: "go"},
	}
	correlated := correlateProcessPorts(items, portMap)
	for _, item := range correlated {
		if len(item.Ports) > 0 {
			t.Fatalf("Process %s unexpectedly received ports from negative PID: %v", item.PID, item.Ports)
		}
	}

	// And process kill validation MUST reject negative PID
	if validatePid("-12") {
		t.Fatalf("validatePid must strictly reject negative PID -12")
	}
}

func TestStressParseSsAdversarial(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name:     "Empty and garbage lines",
			input:    "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\ngarbage\n:::*\n",
			expected: map[string][]string{},
		},
		{
			name: "Multi-process socket sharing with varied PID formats",
			input: `Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:80          0.0.0.0:*         users:(("nginx",pid=701,fd=6),("nginx",pid=702,fd=6),("nginx",pid=703,fd=6))
tcp   LISTEN 0      128    [::]:80             [::]:*            users:(("nginx",pid=701,fd=7),("nginx",pid=702,fd=7),("nginx",pid=703,fd=7))
tcp   LISTEN 0      511    :::443              :::*              users:(("envoy",pid=800,fd=10))
`,
			expected: map[string][]string{
				"701": {"tcp/80"},
				"702": {"tcp/80"},
				"703": {"tcp/80"},
				"800": {"tcp/443"},
			},
		},
		{
			name: "Ignoring non-LISTEN states and missing pid fields",
			input: `State   Recv-Q Send-Q Local Address:Port Peer Address:Port Process
SYN-SENT 0     1      127.0.0.1:9000     127.0.0.1:80      users:(("curl",pid=901,fd=3))
TIME-WAIT 0    0      127.0.0.1:9001     127.0.0.1:80      users:(("curl",pid=902,fd=3))
LISTEN  0      128    127.0.0.1:9002     0.0.0.0:*         users:(("app_no_pid"))
LISTEN  0      128    127.0.0.1:9003     0.0.0.0:*         users:(("app_valid",pid=903,fd=4))
`,
			expected: map[string][]string{
				"903": {"tcp/9003"},
			},
		},
		{
			name: "ss output format without Netid column (6 columns)",
			input: `State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    127.0.0.1:6379     0.0.0.0:*         users:(("redis-server",pid=1101,fd=6))
LISTEN 0      128    [::1]:6379         [::]:*            users:(("redis-server",pid=1101,fd=7))
`,
			expected: map[string][]string{
				"1101": {"tcp/6379"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			portMap := make(map[string][]string)
			parseSsOutput(tc.input, portMap)
			sortPortMap(portMap)

			for pid, expectedPorts := range tc.expected {
				actualPorts, exists := portMap[pid]
				if !exists {
					t.Fatalf("Expected PID %s in portMap, got nothing", pid)
				}
				if !reflect.DeepEqual(actualPorts, expectedPorts) {
					t.Errorf("PID %s got %v, want %v", pid, actualPorts, expectedPorts)
				}
			}

			if len(portMap) != len(tc.expected) {
				t.Errorf("Expected %d PIDs, got %d: %v", len(tc.expected), len(portMap), portMap)
			}
		})
	}
}

func TestStressParseLinuxNetstatAdversarial(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name: "Non-root dash PID program entries and non-TCP protocols",
			input: `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           1234/dhclient
tcp6       0      0 :::80                   :::*                    LISTEN      2001/apache2
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      3001/postgres
tcp        0      0 127.0.0.1:5432          127.0.0.1:45678         ESTABLISHED 3001/postgres
`,
			expected: map[string][]string{
				"2001": {"tcp/80"},
				"3001": {"tcp/5432"},
			},
		},
		{
			name: "IPv6 variations and malformed addresses in netstat",
			input: `Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp6       0      0 :::8080                 :::*                    LISTEN      4001/java
tcp6       0      0 [::]:8443               :::*                    LISTEN      4001/java
tcp6       0      0 ::1:8080                :::*                    LISTEN      4001/java
tcp        0      0 127.0.0.1:invalid       0.0.0.0:*               LISTEN      4002/bad
tcp        0      0 127.0.0.1:99999         0.0.0.0:*               LISTEN      4003/bad
`,
			expected: map[string][]string{
				"4001": {"tcp/8080", "tcp/8443"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			portMap := make(map[string][]string)
			parseLinuxNetstatOutput(tc.input, portMap)
			sortPortMap(portMap)

			for pid, expectedPorts := range tc.expected {
				actualPorts, exists := portMap[pid]
				if !exists {
					t.Fatalf("Expected PID %s in portMap, got nothing", pid)
				}
				if !reflect.DeepEqual(actualPorts, expectedPorts) {
					t.Errorf("PID %s got %v, want %v", pid, actualPorts, expectedPorts)
				}
			}

			if len(portMap) != len(tc.expected) {
				t.Errorf("Expected %d PIDs, got %d: %v", len(tc.expected), len(portMap), portMap)
			}
		})
	}
}

func TestStressParseWindowsNetstatAdversarial(t *testing.T) {
	input := `Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       884
  TCP    127.0.0.1:3000         0.0.0.0:0              LISTENING       5678
  TCP    [::]:3000              [::]:0                 LISTENING       5678
  TCP    [::1]:3000             [::]:0                 LISTENING       5678
  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       5678
  UDP    0.0.0.0:5353           *:*                                    1200
  TCP    192.168.1.10:443       1.2.3.4:50000          ESTABLISHED     3400
  TCP    127.0.0.1:invalid      0.0.0.0:0              LISTENING       9999
  TCP    127.0.0.1:80           0.0.0.0:0              LISTENING       not_a_pid
`
	portMap := make(map[string][]string)
	parseWindowsNetstatOutput(input, portMap)
	sortPortMap(portMap)

	expected := map[string][]string{
		"884":  {"tcp/135"},
		"5678": {"tcp/3000", "tcp/5000"}, // Deduplicated 3000 and sorted before 5000
	}

	if !reflect.DeepEqual(portMap, expected) {
		t.Errorf("Windows netstat got %v, want %v", portMap, expected)
	}
}

func TestStressHighVolumePortMapSorting(t *testing.T) {
	// Stress test with 10,000 socket records across multiple PIDs
	portMap := make(map[string][]string)
	for i := 1; i <= 10000; i++ {
		pid := strconv.Itoa(i % 50)
		port := fmt.Sprintf("tcp/%d", (i*37)%65535+1)
		addUniquePort(portMap, pid, port)
	}

	start := time.Now()
	sortPortMap(portMap)
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Errorf("sortPortMap took too long for 10k items: %v", elapsed)
	}

	// Verify numerical order for each PID
	for pid, ports := range portMap {
		for j := 1; j < len(ports); j++ {
			p1 := extractPortNumber(ports[j-1])
			p2 := extractPortNumber(ports[j])
			if p1 > p2 {
				t.Fatalf("Port list for PID %s not sorted numerically: %v", pid, ports)
			}
		}
	}
}

// --- Section 2: Process Kill Adversarial Validation & HTTP Methods ---

func TestStressProcessKillHTTPMethods(t *testing.T) {
	agent := NewAgentServer("test-token", false)

	methodsToReject := []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
	}

	for _, m := range methodsToReject {
		t.Run("Reject_"+m, func(t *testing.T) {
			req := httptest.NewRequest(m, "/api/process/kill?pid=1234", nil)
			w := httptest.NewRecorder()
			agent.handleProcessKill(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("Method %s expected 405 Method Not Allowed, got %d", m, w.Code)
			}
			if w.Header().Get("Allow") != "POST" {
				t.Errorf("Method %s expected Allow: POST header, got %q", m, w.Header().Get("Allow"))
			}

			var resp ProcessKillResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode JSON response for method %s: %v", m, err)
			}
			if resp.Status != "error" {
				t.Errorf("Expected status 'error', got %q", resp.Status)
			}
		})
	}
}

func TestStressProcessKillAdversarialPIDs(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	selfPID := os.Getpid()

	cases := []struct {
		name       string
		payload    string
		wantStatus int
		errSubstr  string
	}{
		// System protection guards
		{
			name:       "Init process PID 1",
			payload:    `{"pid": 1}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "refusing to terminate system init (PID 1)",
		},
		{
			name:       "Init process PID 1 string",
			payload:    `{"pid": "1"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "refusing to terminate system init (PID 1)",
		},
		{
			name:       "Self agent PID integer",
			payload:    fmt.Sprintf(`{"pid": %d}`, selfPID),
			wantStatus: http.StatusBadRequest,
			errSubstr:  "refusing to terminate agent process itself",
		},
		{
			name:       "Self agent PID string",
			payload:    fmt.Sprintf(`{"pid": "%d"}`, selfPID),
			wantStatus: http.StatusBadRequest,
			errSubstr:  "refusing to terminate agent process itself",
		},
		// Zero and negative PIDs (Unix kill broadcast attacks)
		{
			name:       "Zero PID integer",
			payload:    `{"pid": 0}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Zero PID string",
			payload:    `{"pid": "0"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Negative PID -1 integer (kill all broadcast)",
			payload:    `{"pid": -1}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Negative PID -1 string",
			payload:    `{"pid": "-1"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Negative process group PID -999",
			payload:    `{"pid": "-999"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		// Malformed non-numeric types and injection attempts
		{
			name:       "Alpha string PID",
			payload:    `{"pid": "killme"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Shell injection semicolon",
			payload:    `{"pid": "1234; reboot"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Shell injection pipe",
			payload:    `{"pid": "1234 | rm -rf /"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Shell injection backticks",
			payload:    `{"pid": "` + "`whoami`" + `"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Shell injection subshell",
			payload:    `{"pid": "$(id)"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		// Boundary overflow PIDs
		{
			name:       "Massive PID overflow 10 nines",
			payload:    `{"pid": 9999999999}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "PID exceeding macOS limit 4194305",
			payload:    `{"pid": 4194305}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		// Non-primitive JSON types
		{
			name:       "Boolean PID",
			payload:    `{"pid": true}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
		{
			name:       "Array PID",
			payload:    `{"pid": [1234]}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
		{
			name:       "Object PID",
			payload:    `{"pid": {"id": 1234}}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
		{
			name:       "Null PID",
			payload:    `{"pid": null}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
		{
			name:       "Empty JSON object",
			payload:    `{}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
		{
			name:       "Garbage JSON body",
			payload:    `{not valid json}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(tc.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			agent.handleProcessKill(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("Expected status %d, got %d. Body: %s", tc.wantStatus, w.Code, w.Body.String())
			}

			var resp ProcessKillResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode JSON response: %v", err)
			}
			if !strings.Contains(resp.Error, tc.errSubstr) {
				t.Errorf("Expected error containing %q, got %q", tc.errSubstr, resp.Error)
			}
		})
	}
}

func TestStressProcessKillSignals(t *testing.T) {
	agent := NewAgentServer("test-token", false)

	// Valid signals should not be rejected by signal validation
	// Note: We use a non-existent PID (e.g. 4194300) so it fails at OS execution, NOT at signal validation
	validSignals := []string{
		"",        // defaults to SIGTERM
		"SIGTERM", // standard graceful
		"sigterm", // case-insensitive
		"15",      // numeric SIGTERM
		"SIGKILL", // force kill
		"sigkill", // case-insensitive
		"9",       // numeric SIGKILL
	}

	for _, sig := range validSignals {
		t.Run("ValidSignal_"+sig, func(t *testing.T) {
			payload := fmt.Sprintf(`{"pid": 4194300, "signal": %q}`, sig)
			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
			w := httptest.NewRecorder()
			agent.handleProcessKill(w, req)

			var resp ProcessKillResponse
			_ = json.NewDecoder(w.Body).Decode(&resp)

			// Should NOT fail with 400 "unsupported signal"
			if w.Code == http.StatusBadRequest && strings.Contains(resp.Error, "unsupported signal") {
				t.Errorf("Valid signal %q was unexpectedly rejected with 400: %v", sig, resp.Error)
			}
		})
	}

	// Invalid / Tampered signals must be rejected with 400 Bad Request
	tamperedSignals := []string{
		"SIGFOO",
		"SIGINT",
		"SIGSTOP",
		"SIGSEGV",
		"SIGUSR1",
		"SIGHUP",
		"-9",
		"-15",
		"0",
		"9; rm -rf /",
		"SIG\nKILL",
		"SIGKILL_TAMPERED",
		"kill",
	}

	for _, sig := range tamperedSignals {
		t.Run("RejectSignal_"+sig, func(t *testing.T) {
			payload := fmt.Sprintf(`{"pid": 12345, "signal": %q}`, sig)
			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
			w := httptest.NewRecorder()
			agent.handleProcessKill(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("Expected 400 Bad Request for signal %q, got %d. Body: %s", sig, w.Code, w.Body.String())
			}

			var resp ProcessKillResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode JSON response: %v", err)
			}
			if !strings.Contains(resp.Error, "unsupported signal") {
				t.Errorf("Expected 'unsupported signal' error, got %q", resp.Error)
			}
		})
	}
}

// --- Section 3: End-to-End Live Execution & Concurrent Stress Tests ---

func TestStressLiveSubprocessKillBothSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping live child process kill on Windows in CI")
	}

	agent := NewAgentServer("test-token", false)

	// Test 1: Live SIGTERM termination
	t.Run("Live_SIGTERM", func(t *testing.T) {
		cmd := exec.Command("sleep", "60")
		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start dummy sleep process: %v", err)
		}
		pidStr := strconv.Itoa(cmd.Process.Pid)
		defer func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

		payload := fmt.Sprintf(`{"pid": "%s", "signal": "SIGTERM"}`, pidStr)
		req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		agent.handleProcessKill(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK for live SIGTERM, got %d: %s", w.Code, w.Body.String())
		}

		var resp ProcessKillResponse
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp.Status != "killed" || resp.Signal != "SIGTERM" || resp.PID != pidStr {
			t.Errorf("Unexpected response: %+v", resp)
		}

		// Wait for process exit confirmation
		err := cmd.Wait()
		if err == nil {
			t.Errorf("Expected process to exit with signal error, but got nil")
		}
	})

	// Test 2: Live SIGKILL (force) termination via numeric signal "9"
	t.Run("Live_SIGKILL_Numeric9", func(t *testing.T) {
		cmd := exec.Command("sleep", "60")
		if err := cmd.Start(); err != nil {
			t.Fatalf("Failed to start dummy sleep process: %v", err)
		}
		pidStr := strconv.Itoa(cmd.Process.Pid)
		defer func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}()

		payload := fmt.Sprintf(`{"pid": %s, "signal": "9"}`, pidStr)
		req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		agent.handleProcessKill(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK for live SIGKILL, got %d: %s", w.Code, w.Body.String())
		}

		var resp ProcessKillResponse
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if resp.Status != "killed" || resp.Signal != "SIGKILL" || resp.PID != pidStr {
			t.Errorf("Unexpected response: %+v", resp)
		}

		err := cmd.Wait()
		if err == nil {
			t.Errorf("Expected process to exit with signal error, but got nil")
		}
	})

	// Test 3: Attempt to kill non-existent process gracefully returns 500 without crashing daemon
	t.Run("Kill_NonExistent_Process_Returns_500_Gracefully", func(t *testing.T) {
		payload := `{"pid": 4194300, "signal": "SIGTERM"}`
		req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
		w := httptest.NewRecorder()
		agent.handleProcessKill(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("Expected 500 InternalServerError for dead PID, got %d: %s", w.Code, w.Body.String())
		}

		var resp ProcessKillResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode JSON response: %v", err)
		}
		if resp.Status != "error" || resp.PID != "4194300" {
			t.Errorf("Unexpected response: %+v", resp)
		}
	})
}

func TestStressConcurrentProcessKillAttacks(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	const concurrency = 50

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			var payload string
			switch idx % 5 {
			case 0:
				payload = `{"pid": 1}` // init guard
			case 1:
				payload = `{"pid": 0}` // zero guard
			case 2:
				payload = `{"pid": -1}` // negative guard
			case 3:
				payload = `{"pid": "malformed_injection; reboot"}`
			case 4:
				payload = `{"pid": 12345, "signal": "SIGFOO"}`
			}

			req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
			w := httptest.NewRecorder()
			agent.handleProcessKill(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Worker %d expected status 400, got %d: %s", idx, w.Code, w.Body.String())
			}
		}(i)
	}

	wg.Wait()
}

func TestStressFullRouteProtectionChain(t *testing.T) {
	token := "secure-test-token-12345"
	agent := NewAgentServer(token, false)
	handler := agent.Routes()

	// 1. Missing Token on /api/process/list -> 401
	t.Run("ProcessList_MissingToken_401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/process/list", nil)
		req.Host = "127.0.0.1:9921"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. DNS Rebinding / Public Host on /api/process/list -> 403
	t.Run("ProcessList_PublicHost_403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/process/list", nil)
		req.Host = "attacker.com:9921"
		req.Header.Set("X-EF-Token", token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for public host, got %d", w.Code)
		}
	})

	// 3. Untrusted Origin on /api/process/kill -> 403
	t.Run("ProcessKill_UntrustedOrigin_403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(`{"pid": 100}`))
		req.Host = "127.0.0.1:9921"
		req.Header.Set("Origin", "http://evil-site.com")
		req.Header.Set("X-EF-Token", token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for untrusted origin, got %d", w.Code)
		}
	})

	// 4. Valid Loopback Host & Token on /api/process/list -> 200
	t.Run("ProcessList_ValidAuth_200", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req := httptest.NewRequest(http.MethodGet, "/api/process/list", nil).WithContext(ctx)
		req.Host = "127.0.0.1:9921"
		req.Header.Set("X-EF-Token", token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK for authenticated process list, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response JSON: %v", err)
		}
		if resp["status"] != "success" {
			t.Errorf("Expected status 'success', got %v", resp["status"])
		}
		procs, ok := resp["processes"].([]interface{})
		if !ok || len(procs) == 0 {
			t.Errorf("Expected non-empty processes list, got %v", resp["processes"])
		}
	})
}
