package main

import (
	"bytes"
	"encoding/json"
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

// --- F1: Port Parser Unit Tests ---

func TestParseLsofOutput(t *testing.T) {
	sample := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Antigravi   107 jinhan   34u  IPv4 0x33ffa09eacfa6a60      0t0  TCP 127.0.0.1:53148 (LISTEN)
Antigravi   107 jinhan   37u  IPv4 0x62a882081fcb88c5      0t0  TCP 127.0.0.1:53152 (LISTEN)
rapportd    704 jinhan   15u  IPv6 0x5e5db674e989e36c      0t0  TCP *:61657 (LISTEN)
Parallels  2268 jinhan   11u  IPv6 0x5a54245d52196000      0t0  TCP [::1]:57889 (LISTEN)
Parallels  2268 jinhan   12u  IPv4 0xa338e32d2ecd2f30      0t0  TCP 127.0.0.1:57889 (LISTEN)
Code\x20H 23328 jinhan   42u  IPv4 0x805f764ef53c7826      0t0  TCP 127.0.0.1:50902 (LISTEN)
invalid_line_without_enough_fields
`
	portMap := make(map[string][]string)
	parseLsofOutput(sample, portMap)
	sortPortMap(portMap)

	expected107 := []string{"tcp/53148", "tcp/53152"}
	if !reflect.DeepEqual(portMap["107"], expected107) {
		t.Errorf("PID 107 got %v, want %v", portMap["107"], expected107)
	}

	expected704 := []string{"tcp/61657"}
	if !reflect.DeepEqual(portMap["704"], expected704) {
		t.Errorf("PID 704 got %v, want %v", portMap["704"], expected704)
	}

	// Verify deduplication across IPv4 and IPv6 for PID 2268
	expected2268 := []string{"tcp/57889"}
	if !reflect.DeepEqual(portMap["2268"], expected2268) {
		t.Errorf("PID 2268 got %v, want %v (deduplication check)", portMap["2268"], expected2268)
	}

	expected23328 := []string{"tcp/50902"}
	if !reflect.DeepEqual(portMap["23328"], expected23328) {
		t.Errorf("PID 23328 got %v, want %v", portMap["23328"], expected23328)
	}
}

func TestParseSsOutput(t *testing.T) {
	sample := `State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
LISTEN  0       128     0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
LISTEN  0       511     127.0.0.1:3000       0.0.0.0:*          users:(("node",pid=5678,fd=19))
LISTEN  0       128     [::]:80              [::]:*             users:(("nginx",pid=9012,fd=6),("nginx",pid=9013,fd=6))
LISTEN  0       128     :::9921              :::*               users:(("agent",pid=4242,fd=3))
ESTAB   0       0       127.0.0.1:54321      127.0.0.1:80       users:(("curl",pid=9999,fd=3))
`
	portMap := make(map[string][]string)
	parseSsOutput(sample, portMap)
	sortPortMap(portMap)

	if !reflect.DeepEqual(portMap["1234"], []string{"tcp/22"}) {
		t.Errorf("PID 1234 got %v, want [tcp/22]", portMap["1234"])
	}
	if !reflect.DeepEqual(portMap["5678"], []string{"tcp/3000"}) {
		t.Errorf("PID 5678 got %v, want [tcp/3000]", portMap["5678"])
	}
	// Multi-process socket sharing
	if !reflect.DeepEqual(portMap["9012"], []string{"tcp/80"}) {
		t.Errorf("PID 9012 got %v, want [tcp/80]", portMap["9012"])
	}
	if !reflect.DeepEqual(portMap["9013"], []string{"tcp/80"}) {
		t.Errorf("PID 9013 got %v, want [tcp/80]", portMap["9013"])
	}
	if !reflect.DeepEqual(portMap["4242"], []string{"tcp/9921"}) {
		t.Errorf("PID 4242 got %v, want [tcp/9921]", portMap["4242"])
	}
	// ESTAB non-LISTEN connection ignored
	if _, ok := portMap["9999"]; ok {
		t.Errorf("ESTAB connection should not be included in portMap")
	}
}

func TestParseLinuxNetstatOutput(t *testing.T) {
	sample := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      5678/node
tcp6       0      0 :::80                   :::*                    LISTEN      9012/nginx
tcp        0      0 192.168.1.1:443         1.2.3.4:5678            ESTABLISHED 1122/curl
`
	portMap := make(map[string][]string)
	parseLinuxNetstatOutput(sample, portMap)
	sortPortMap(portMap)

	if !reflect.DeepEqual(portMap["1234"], []string{"tcp/22"}) {
		t.Errorf("PID 1234 got %v, want [tcp/22]", portMap["1234"])
	}
	if !reflect.DeepEqual(portMap["5678"], []string{"tcp/3000"}) {
		t.Errorf("PID 5678 got %v, want [tcp/3000]", portMap["5678"])
	}
	if !reflect.DeepEqual(portMap["9012"], []string{"tcp/80"}) {
		t.Errorf("PID 9012 got %v, want [tcp/80]", portMap["9012"])
	}
	if _, ok := portMap["1122"]; ok {
		t.Errorf("ESTABLISHED connection should not be in portMap")
	}
}

func TestParseWindowsNetstatOutput(t *testing.T) {
	sample := `Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       884
  TCP    127.0.0.1:3000         0.0.0.0:0              LISTENING       5678
  TCP    [::]:80                [::]:0                 LISTENING       9012
  TCP    [::1]:3000             [::]:0                 LISTENING       5678
  TCP    192.168.1.50:52134     142.250.190.46:443     ESTABLISHED     1122
`
	portMap := make(map[string][]string)
	parseWindowsNetstatOutput(sample, portMap)
	sortPortMap(portMap)

	if !reflect.DeepEqual(portMap["884"], []string{"tcp/135"}) {
		t.Errorf("PID 884 got %v, want [tcp/135]", portMap["884"])
	}
	// Deduplication across IPv4 and IPv6
	if !reflect.DeepEqual(portMap["5678"], []string{"tcp/3000"}) {
		t.Errorf("PID 5678 got %v, want [tcp/3000]", portMap["5678"])
	}
	if !reflect.DeepEqual(portMap["9012"], []string{"tcp/80"}) {
		t.Errorf("PID 9012 got %v, want [tcp/80]", portMap["9012"])
	}
	if _, ok := portMap["1122"]; ok {
		t.Errorf("PID 1122 (ESTABLISHED) should not be in portMap")
	}
}

func TestSortPortMap(t *testing.T) {
	portMap := map[string][]string{
		"100": {"tcp/8080", "tcp/80", "tcp/3000", "tcp/443"},
	}
	sortPortMap(portMap)
	expected := []string{"tcp/80", "tcp/443", "tcp/3000", "tcp/8080"}
	if !reflect.DeepEqual(portMap["100"], expected) {
		t.Errorf("Numeric sort failed: got %v, want %v", portMap["100"], expected)
	}
}

func TestCorrelateProcessPorts(t *testing.T) {
	items := []ProcessItem{
		{PID: "100", Name: "node"},
		{PID: "200", Name: "bash"},
	}
	portMap := map[string][]string{
		"100": {"tcp/3000"},
	}
	correlated := correlateProcessPorts(items, portMap)

	if len(correlated[0].Ports) != 1 || correlated[0].Ports[0] != "tcp/3000" {
		t.Errorf("Expected node to have port tcp/3000, got %v", correlated[0].Ports)
	}
	if len(correlated[1].Ports) != 0 {
		t.Errorf("Expected bash to have no ports, got %v", correlated[1].Ports)
	}
}

// --- F2: Process Kill Handler Unit Tests ---

func TestProcessKillMethodRestriction(t *testing.T) {
	agent := NewAgentServer("test-token", false)

	// GET must be rejected with 405 Method Not Allowed
	req := httptest.NewRequest(http.MethodGet, "/api/process/kill?pid=1234", nil)
	w := httptest.NewRecorder()
	agent.handleProcessKill(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed for GET, got %d", w.Code)
	}
	if w.Header().Get("Allow") != "POST" {
		t.Errorf("Expected Allow header to contain POST, got %q", w.Header().Get("Allow"))
	}
}

func TestProcessKillValidationGuards(t *testing.T) {
	agent := NewAgentServer("test-token", false)

	cases := []struct {
		name       string
		body       string
		query      string
		wantStatus int
		errSubstr  string
	}{
		{
			name:       "Missing PID completely",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "missing pid parameter",
		},
		{
			name:       "Alpha PID",
			body:       `{"pid": "abc"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Negative PID",
			body:       `{"pid": "-1"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Zero PID",
			body:       `{"pid": 0}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "invalid pid",
		},
		{
			name:       "Init process PID 1 rejection",
			body:       `{"pid": 1}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "refusing to terminate system init (PID 1)",
		},
		{
			name:       "Self process rejection",
			body:       `{"pid": ` + strconv.Itoa(os.Getpid()) + `}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "refusing to terminate agent process itself",
		},
		{
			name:       "Invalid signal parameter",
			body:       `{"pid": 1234, "signal": "SIGSTOP"}`,
			wantStatus: http.StatusBadRequest,
			errSubstr:  "unsupported signal",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != "" {
				req = httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(tc.body))
			} else {
				req = httptest.NewRequest(http.MethodPost, "/api/process/kill?"+tc.query, nil)
			}
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

func TestProcessKillSafeDummyProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping live child process kill test on Windows in CI environment")
	}

	agent := NewAgentServer("test-token", false)

	// Spawn a safe dummy sleep process
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start dummy sleep process: %v", err)
	}
	dummyPid := strconv.Itoa(cmd.Process.Pid)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Send POST /api/process/kill with JSON payload and SIGTERM
	payload := `{"pid": "` + dummyPid + `", "signal": "SIGTERM"}`
	req := httptest.NewRequest(http.MethodPost, "/api/process/kill", bytes.NewBufferString(payload))
	w := httptest.NewRecorder()
	agent.handleProcessKill(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for killing dummy process, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp ProcessKillResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Status != "killed" {
		t.Errorf("Expected status 'killed', got %q", resp.Status)
	}
	if resp.PID != dummyPid {
		t.Errorf("Expected PID %q, got %q", dummyPid, resp.PID)
	}
	if resp.Signal != "SIGTERM" {
		t.Errorf("Expected signal SIGTERM, got %q", resp.Signal)
	}

	// Confirm dummy process has exited
	err := cmd.Wait()
	if err == nil {
		t.Errorf("Expected error from terminated process, got nil")
	}
}
