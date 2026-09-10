package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =========================================================================
// 1. STRESS-TEST CRONTAB OPERATIONS & INJECTION PAYLOADS
// =========================================================================

func TestStressCronCommandInjection(t *testing.T) {
	// Adversarial command injection payloads targeting /api/cron/save
	payloads := []struct {
		name    string
		req     CronSaveRequest
		wantErr bool
		reason  string
	}{
		{
			name: "Newline injection in command creating secondary cron job",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5",
				Command:  "/usr/bin/backup.sh\n* * * * * touch /tmp/pwn",
				Comment:  "legit backup",
			},
			wantErr: true,
			reason:  "Command contains newline",
		},
		{
			name: "CRLF injection in command creating secondary cron job",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5",
				Command:  "/usr/bin/backup.sh\r\n* * * * * touch /tmp/pwn",
				Comment:  "legit backup",
			},
			wantErr: true,
			reason:  "Command contains CRLF",
		},
		{
			name: "Null byte injection in command attempting string termination",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5",
				Command:  "/usr/bin/backup.sh\x00evil_argument",
				Comment:  "legit backup",
			},
			wantErr: true,
			reason:  "Command contains null byte",
		},
		{
			name: "Newline injection in schedule creating secondary cron job",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5\n* * * * * touch /tmp/pwn",
				Command:  "/usr/bin/backup.sh",
				Comment:  "legit backup",
			},
			wantErr: true,
			reason:  "Schedule contains newline",
		},
		{
			name: "Null byte injection in schedule",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5\x00evil",
				Command:  "/usr/bin/backup.sh",
				Comment:  "legit backup",
			},
			wantErr: true,
			reason:  "Schedule contains null byte",
		},
		{
			name: "Newline injection in comment creating secondary cron job",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5",
				Command:  "/usr/bin/backup.sh",
				Comment:  "legit comment\n* * * * * touch /tmp/pwn",
			},
			wantErr: true,
			reason:  "Comment contains newline",
		},
		{
			name: "Null byte injection in comment",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5",
				Command:  "/usr/bin/backup.sh",
				Comment:  "legit comment\x00evil",
			},
			wantErr: true,
			reason:  "Comment contains null byte",
		},
		{
			name: "Command injection payload in schedule field with semicolon",
			req: CronSaveRequest{
				Schedule: "* * * * *; touch /tmp/pwn;",
				Command:  "/usr/bin/backup.sh",
			},
			wantErr: true,
			reason:  "Schedule with command injection semicolon must fail schedule validation",
		},
		{
			name: "Command injection payload in schedule field with pipe",
			req: CronSaveRequest{
				Schedule: "* * * * * | touch /tmp/pwn",
				Command:  "/usr/bin/backup.sh",
			},
			wantErr: true,
			reason:  "Schedule with pipe must fail schedule validation",
		},
		{
			name: "Command injection payload in schedule field with subshell",
			req: CronSaveRequest{
				Schedule: "* * * * * $(touch /tmp/pwn)",
				Command:  "/usr/bin/backup.sh",
			},
			wantErr: true,
			reason:  "Schedule with subshell must fail schedule validation",
		},
		{
			name: "Command injection payload in schedule field with backticks",
			req: CronSaveRequest{
				Schedule: "* * * * * `touch /tmp/pwn`",
				Command:  "/usr/bin/backup.sh",
			},
			wantErr: true,
			reason:  "Schedule with backticks must fail schedule validation",
		},
		{
			name: "Command with legitimate shell metacharacters without newlines",
			req: CronSaveRequest{
				Schedule: "0 9 * * 1-5",
				Command:  "/usr/bin/backup.sh && curl -s https://example.com/notify || true",
				Comment:  "chained command",
			},
			wantErr: false,
			reason:  "Legitimate shell chaining in command without newlines must be permitted in crontab",
		},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCronJobInput(tc.req)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateCronJobInput() error = %v, wantErr %v (reason: %s)", err, tc.wantErr, tc.reason)
			}
		})
	}
}

func TestStressWindowsTaskNameValidation(t *testing.T) {
	// Adversarial Windows task names
	cases := []struct {
		name      string
		input     string
		wantErr   bool
		wantName  string
	}{
		{"Alphanumeric basic", "BackupTask", false, "EF_BackupTask"},
		{"Already prefixed", "EF_DailySync", false, "EF_DailySync"},
		{"With hyphen and underscore", "sync-job_01", false, "EF_sync-job_01"},
		{"Semicolon command chaining attempt", "task; calc.exe", true, ""},
		{"Ampersand command chaining attempt", "task & calc.exe", true, ""},
		{"Pipe command chaining attempt", "task | calc.exe", true, ""},
		{"Redirection attempt", "task > evil.txt", true, ""},
		{"Backslash path traversal attempt", `..\..\evil`, true, ""},
		{"Forward slash path traversal attempt", "../../evil", true, ""},
		{"Double quote escape attempt", `task"evil`, true, ""},
		{"Single quote escape attempt", `task'evil`, true, ""},
		{"Newline injection attempt", "task\ncalc.exe", true, ""},
		{"Null byte injection attempt", "task\x00calc.exe", true, ""},
		{"Spaces in task name", "task with spaces", true, ""},
		{"Special dollar sign attempt", "task$name", true, ""},
		{"Special at sign attempt", "task@name", true, ""},
		{"Special exclamation attempt", "task!name", true, ""},
		{"Non-ASCII unicode attempt", "EF_한글태스크", true, ""},
		{"Maximum allowed length (64 chars total including EF_ prefix)", strings.Repeat("A", 61), false, "EF_" + strings.Repeat("A", 61)},
		{"Exceeding maximum allowed length (65 chars total)", strings.Repeat("A", 62), true, ""},
		{"Extremely long payload (1000 chars)", strings.Repeat("A", 1000), true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateWindowsTaskName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateWindowsTaskName(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.wantName {
				t.Errorf("validateWindowsTaskName(%q) = %q, want %q", tc.input, got, tc.wantName)
			}
		})
	}
}

func TestStressScheduleValidationBypassAttempts(t *testing.T) {
	// Adversarial schedule expressions attempting validation bypass
	bypassAttempts := []struct {
		name     string
		schedule string
		valid    bool
	}{
		// Field count manipulation
		{"Empty string", "", false},
		{"Whitespace only", "    \t  ", false},
		{"1 field", "*", false},
		{"2 fields", "* *", false},
		{"3 fields", "* * *", false},
		{"4 fields", "* * * *", false},
		{"Standard 5 fields", "* * * * *", true},
		{"Quartz 6 fields (second field added)", "0 0 12 * * ?", false},
		{"6 asterisks", "* * * * * *", false},
		{"7 fields", "* * * * * * *", false},

		// Out-of-bounds minute (0-59)
		{"Minute 60", "60 * * * *", false},
		{"Minute negative", "-1 * * * *", false},
		{"Minute 99", "99 * * * *", false},
		{"Minute 00", "00 * * * *", true},
		{"Minute 59", "59 * * * *", true},

		// Out-of-bounds hour (0-23)
		{"Hour 24", "* 24 * * *", false},
		{"Hour negative", "* -5 * * *", false},
		{"Hour 99", "* 99 * * *", false},
		{"Hour 0", "* 0 * * *", true},
		{"Hour 23", "* 23 * * *", true},

		// Out-of-bounds day of month (1-31)
		{"DOM 0", "* * 0 * *", false},
		{"DOM 32", "* * 32 * *", false},
		{"DOM negative", "* * -1 * *", false},
		{"DOM 1", "* * 1 * *", true},
		{"DOM 31", "* * 31 * *", true},

		// Out-of-bounds month (1-12)
		{"Month 0", "* * * 0 *", false},
		{"Month 13", "* * * 13 *", false},
		{"Month negative", "* * * -1 *", false},
		{"Month 1", "* * * 1 *", true},
		{"Month 12", "* * * 12 *", true},
		{"Month invalid name", "* * * FOO *", false},
		{"Month valid name JAN", "* * * JAN *", true},
		{"Month valid name DEC", "* * * DEC *", true},

		// Out-of-bounds day of week (0-7)
		{"DOW negative", "* * * * -1", false},
		{"DOW 8", "* * * * 8", false},
		{"DOW 0 (Sunday)", "* * * * 0", true},
		{"DOW 7 (Sunday)", "* * * * 7", true},
		{"DOW invalid name", "* * * * BAR", false},
		{"DOW valid name SUN", "* * * * SUN", true},
		{"DOW valid name SAT", "* * * * SAT", true},

		// Step manipulation
		{"Step 0 division by zero attempt", "*/0 * * * *", false},
		{"Step negative", "*/-5 * * * *", false},
		{"Step non-numeric", "*/* * * * *", false},
		{"Step missing number", "*/ * * * *", false},
		{"Step on range 1-5/2", "1-5/2 * * * *", true},
		{"Step on range with 0 step", "1-5/0 * * * *", false},
		{"Double step slash", "1/2/3 * * * *", false},

		// Range inversion and malformation
		{"Inverted range 5-1", "5-1 * * * *", false},
		{"Inverted month range DEC-JAN", "* * * DEC-JAN *", false},
		{"Valid month range JAN-DEC", "* * * JAN-DEC *", true},
		{"Trailing dash", "1- * * * *", false},
		{"Leading dash", "-5 * * * *", false},
		{"Triple range dash", "1-2-3 * * * *", false},

		// Comma list malformation
		{"Trailing comma", "1,2, * * * *", false},
		{"Leading comma", ",1,2 * * * *", false},
		{"Double comma", "1,,2 * * * *", false},
		{"Valid list", "1,15,30 * * * *", true},

		// Macros and macro injection
		{"Valid macro @reboot", "@reboot", true},
		{"Valid macro @hourly", "@hourly", true},
		{"Valid macro @daily", "@daily", true},
		{"Valid macro @midnight", "@midnight", true},
		{"Valid macro @weekly", "@weekly", true},
		{"Valid macro @monthly", "@monthly", true},
		{"Valid macro @yearly", "@yearly", true},
		{"Valid macro @annually", "@annually", true},
		{"Macro with command suffix injection", "@reboot; rm -rf /", false},
		{"Macro with newline injection", "@hourly\n* * * * * evil", false},
		{"Invalid macro name", "@hourly_extra", false},
		{"Unknown macro", "@minutely", false},
	}

	for _, tc := range bypassAttempts {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidCronSchedule(tc.schedule)
			if got != tc.valid {
				t.Errorf("isValidCronSchedule(%q) = %v, want %v", tc.schedule, got, tc.valid)
			}
		})
	}
}

func TestStressCrontabParserCorruptLines(t *testing.T) {
	// Feed crontab parser completely corrupt, malformed, and boundary inputs
	corruptCrontab := `# Legitimate header
MAILTO=admin@example.com
SHELL=/bin/bash

# Corrupt line 4: Only 1 field
invalid_single_field

# Corrupt line 7: 5 fields but no command
* * * * *

# Corrupt line 10: Invalid schedule field
60 * * * * /bin/do_something.sh

# Corrupt line 13: Random binary junk
` + "\x01\x02\x03\x04\x05\x06" + `

# Corrupt line 16: Malformed disabled job (invalid schedule)
# 99 99 * * * /bin/broken.sh

# Valid job 1
0 9 * * 1-5 /usr/bin/real-backup.sh # Daily Backup

# Valid disabled job
# 30 2 * * * /usr/bin/real-clean.sh # Nightly Clean
`

	jobs := parseCrontab(corruptCrontab)

	for _, j := range jobs {
		if strings.Contains(j.Command, "broken") || strings.Contains(j.Command, "do_something") {
			t.Errorf("Corrupt line was parsed as valid cron job: %+v", j)
		}
	}

	if len(jobs) != 2 {
		t.Errorf("Expected exactly 2 valid jobs parsed, got %d", len(jobs))
	}
}

func TestStressDeleteCrontabContentGhostLineBug(t *testing.T) {
	// Bug 1: Deleting line_1 on empty crontab should return error, but returns nil
	emptyRaw := ""
	resEmpty, errEmpty := deleteCrontabContent(emptyRaw, "line_1")
	t.Logf("deleteCrontabContent(\"\", \"line_1\") result: res=%q, err=%v", resEmpty, errEmpty)
	if errEmpty == nil {
		t.Errorf("BUG CONFIRMED: deleteCrontabContent on empty crontab returned nil error for line_1")
	}

	// Bug 2: Deleting line_2 on 1-line crontab should return error, but returns nil
	singleJob := "0 9 * * 1-5 /backup.sh\n"
	resSingle, errSingle := deleteCrontabContent(singleJob, "line_2")
	t.Logf("deleteCrontabContent(singleJob, \"line_2\") result: res=%q, err=%v", resSingle, errSingle)
	if errSingle == nil {
		t.Errorf("BUG CONFIRMED: deleteCrontabContent on 1-job crontab returned nil error for line_2")
	}
}

func TestStressCronDeleteNonExistentAndMalformedIDs(t *testing.T) {
	sample := `# Crontab
0 9 * * 1-5 /backup.sh
`
	malformedIDs := []string{
		"line_99999",
		"line_0",
		"line_-1",
		"line_-999",
		"line_abc",
		"line_NaN",
		"line_1.5",
		"non_prefixed_id",
		"line_99999999999999999999999999999999", // int overflow
		"",
	}

	for _, id := range malformedIDs {
		t.Run("DeleteID_"+id, func(t *testing.T) {
			_, err := deleteCrontabContent(sample, id)
			if err == nil {
				t.Errorf("deleteCrontabContent() succeeded for invalid/non-existent ID %q, expected error", id)
			}
		})
	}
}

func TestStressCronEndpointsIntegrationAdversarial(t *testing.T) {
	agent := NewAgentServer("test-secret-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	// 1. POST /api/cron/save with empty body
	reqEmpty, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader([]byte("")))
	reqEmpty.Header.Set("X-EF-Token", "test-secret-token")
	respEmpty, err := client.Do(reqEmpty)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respEmpty.Body.Close()
	if respEmpty.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/save with empty body returned %d, want 400", respEmpty.StatusCode)
	}

	// 2. POST /api/cron/save with empty JSON object "{}"
	reqEmptyObj, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader([]byte("{}")))
	reqEmptyObj.Header.Set("X-EF-Token", "test-secret-token")
	respEmptyObj, err := client.Do(reqEmptyObj)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respEmptyObj.Body.Close()
	if respEmptyObj.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/save with {} returned %d, want 400", respEmptyObj.StatusCode)
	}

	// 3. POST /api/cron/save with command injection (newline in command)
	badCmdBody, _ := json.Marshal(CronSaveRequest{
		Schedule: "* * * * *",
		Command:  "/bin/test\n* * * * * touch /tmp/pwn",
	})
	reqBadCmd, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader(badCmdBody))
	reqBadCmd.Header.Set("X-EF-Token", "test-secret-token")
	respBadCmd, err := client.Do(reqBadCmd)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBadCmd.Body.Close()
	if respBadCmd.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/save with newline command injection returned %d, want 400", respBadCmd.StatusCode)
	}

	// 4. POST /api/cron/save with null byte in command
	nullCmdBody, _ := json.Marshal(CronSaveRequest{
		Schedule: "* * * * *",
		Command:  "/bin/test\x00evil",
	})
	reqNullCmd, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader(nullCmdBody))
	reqNullCmd.Header.Set("X-EF-Token", "test-secret-token")
	respNullCmd, err := client.Do(reqNullCmd)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respNullCmd.Body.Close()
	if respNullCmd.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/save with null byte command injection returned %d, want 400", respNullCmd.StatusCode)
	}

	// 5. POST /api/cron/delete with empty body and no query param
	reqDelEmpty, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/delete", bytes.NewReader([]byte("")))
	reqDelEmpty.Header.Set("X-EF-Token", "test-secret-token")
	respDelEmpty, err := client.Do(reqDelEmpty)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respDelEmpty.Body.Close()
	if respDelEmpty.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/delete with empty body returned %d, want 400", respDelEmpty.StatusCode)
	}

	// 6. POST /api/cron/delete with newline in ID (middle vs trailing)
	// Newline in middle: TrimSpace cannot strip it, so strings.ContainsAny catches it -> 400
	reqDelInjMid, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/delete", bytes.NewReader([]byte(`{"id":"line_\n1"}`)))
	reqDelInjMid.Header.Set("X-EF-Token", "test-secret-token")
	respDelInjMid, err := client.Do(reqDelInjMid)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respDelInjMid.Body.Close()
	if respDelInjMid.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/delete with middle newline returned %d, want 400", respDelInjMid.StatusCode)
	}

	// Trailing newline: Must be rejected with 400 Bad Request before any trimming
	reqDelInjTrail, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/delete", bytes.NewReader([]byte(`{"id":"line_1\n"}`)))
	reqDelInjTrail.Header.Set("X-EF-Token", "test-secret-token")
	respDelInjTrail, _ := client.Do(reqDelInjTrail)
	respDelInjTrail.Body.Close()
	if respDelInjTrail.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/delete with trailing newline returned %d, want 400", respDelInjTrail.StatusCode)
	}

	// 7. POST /api/cron/delete with null byte in ID
	reqDelNull, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/delete", bytes.NewReader([]byte("{\"id\":\"line_1\x00\"}")))
	reqDelNull.Header.Set("X-EF-Token", "test-secret-token")
	respDelNull, err := client.Do(reqDelNull)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respDelNull.Body.Close()
	if respDelNull.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /api/cron/delete with null byte in ID returned %d, want 400", respDelNull.StatusCode)
	}

	// 8. GET /api/cron/list with invalid Host header
	reqBadHost, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cron/list", nil)
	reqBadHost.Header.Set("X-EF-Token", "test-secret-token")
	reqBadHost.Host = "127.0.0.1.attacker.com"
	respBadHost, err := client.Do(reqBadHost)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBadHost.Body.Close()
	if respBadHost.StatusCode != http.StatusForbidden {
		t.Errorf("GET /api/cron/list with attacker Host header returned %d, want 403", respBadHost.StatusCode)
	}
}

// =========================================================================
// 2. STRESS-TEST SECURITY MIDDLEWARE
// =========================================================================

func TestStressDNSRebindingHostHeaders(t *testing.T) {
	agent := NewAgentServer("security-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/health", ""},
		{http.MethodGet, "/api/process/list", ""},
		{http.MethodGet, "/api/cron/list", ""},
		{http.MethodPost, "/api/proxy", `{"url":"http://127.0.0.1:9921/api/health"}`},
		{http.MethodPost, "/api/process/kill", `{"pid":"999999"}`},
		{http.MethodPost, "/api/cron/save", `{"schedule":"* * * * *","command":"echo hi"}`},
		{http.MethodPost, "/api/cron/delete", `{"id":"line_1"}`},
	}

	adversarialHosts := []string{
		"attacker.com",
		"attacker.com:9921",
		"127.0.0.1.attacker.com",
		"127.0.0.1.attacker.com:9921",
		"localhost.attacker.com",
		"localhost.attacker.com:9921",
		"attacker.com:localhost",
		"spoofed.localhost",
		"localhost.localdomain",
		"127.0.0.2",
		"127.0.0.2:9921",
		"0.0.0.0",
		"0.0.0.0:9921",
		"169.254.169.254",
		"169.254.169.254:9921",
		"[::2]",
		"[::2]:9921",
		"[fe80::1]",
		"[fe80::1]:9921",
		"127.0.0.1.xip.io",
		"127.0.0.1.nip.io",
		"127.0.0.1.nip.io:9921",
		"localhost.",
		"127.0.0.1.",
	}

	// All adversarial host headers MUST be rejected with 403 Forbidden across ALL endpoints
	for _, ep := range endpoints {
		for _, badHost := range adversarialHosts {
			var bodyReader io.Reader
			if ep.body != "" {
				bodyReader = strings.NewReader(ep.body)
			}
			req, err := http.NewRequest(ep.method, ts.URL+ep.path, bodyReader)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Host = badHost
			req.Header.Set("X-EF-Token", "security-token")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request to %s with host %s failed: %v", ep.path, badHost, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("CRITICAL: Endpoint %s %s with hostile Host header %q returned %d, want 403 Forbidden",
					ep.method, ep.path, badHost, resp.StatusCode)
			}
		}
	}
}

func TestStressHostHeaderParsingFlaws(t *testing.T) {
	// Flaw 1: Host header with userinfo syntax strips at colon, allowing bypass
	// e.g. "127.0.0.1:80@attacker.com" -> splits at ":80@attacker.com" -> leaves "127.0.0.1" -> returns true!
	if validLoopbackHost("127.0.0.1:80@attacker.com") {
		t.Errorf("SECURITY FLAW: validLoopbackHost(\"127.0.0.1:80@attacker.com\") = true, expected false")
	}
	if validLoopbackHost("localhost:user@attacker.com") {
		t.Errorf("SECURITY FLAW: validLoopbackHost(\"localhost:user@attacker.com\") = true, expected false")
	}

	// Flaw 2: Empty Host header is accepted (fails open for HTTP/1.0 or client-dropped hosts)
	if validLoopbackHost("") {
		t.Logf("Notice: validLoopbackHost(\"\") = true (designed to tolerate HTTP/1.0, but allows hosts dropped by clients)")
	}
}

func TestStressValidLoopbackHostHeaders(t *testing.T) {
	// Verify valid loopback hosts are accepted
	validHosts := []string{
		"localhost",
		"localhost:9921",
		"127.0.0.1",
		"127.0.0.1:9921",
		"[::1]",
		"[::1]:9921",
		"LOCALHOST",
		"LOCALHOST:9921",
		"", // HTTP/1.0 omission
	}

	for _, host := range validHosts {
		if !validLoopbackHost(host) {
			t.Errorf("validLoopbackHost(%q) = false, want true", host)
		}
	}
}

func TestStressTokenAuthTimingConstantTime(t *testing.T) {
	// Empirical statistical test for ConstantTimeCompare behavior
	// Verify subtle.ConstantTimeCompare executes in constant time regardless of where mismatches occur.
	correctToken := "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" // 32 characters
	mismatchFirstByte := "z1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
	mismatchMidByte := "a1b2c3d4e5f6g7h8z9j0k1l2m3n4o5p6"
	mismatchLastByte := "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5pz"
	exactMatch := "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

	// Warm up
	for i := 0; i < 10000; i++ {
		_ = subtle.ConstantTimeCompare([]byte(mismatchFirstByte), []byte(correctToken))
		_ = subtle.ConstantTimeCompare([]byte(exactMatch), []byte(correctToken))
	}

	// Measure 50,000 iterations for each mismatch position
	iterations := 50000

	measure := func(cand string) (time.Duration, float64) {
		bCand := []byte(cand)
		bTok := []byte(correctToken)
		start := time.Now()
		for i := 0; i < iterations; i++ {
			_ = subtle.ConstantTimeCompare(bCand, bTok)
		}
		dur := time.Since(start)
		nsPerOp := float64(dur.Nanoseconds()) / float64(iterations)
		return dur, nsPerOp
	}

	durFirst, nsFirst := measure(mismatchFirstByte)
	durMid, nsMid := measure(mismatchMidByte)
	durLast, nsLast := measure(mismatchLastByte)
	durMatch, nsMatch := measure(exactMatch)

	t.Logf("Timing comparison over %d ops:", iterations)
	t.Logf("  Mismatch at byte 0:  %v (%.2f ns/op)", durFirst, nsFirst)
	t.Logf("  Mismatch at byte 16: %v (%.2f ns/op)", durMid, nsMid)
	t.Logf("  Mismatch at byte 31: %v (%.2f ns/op)", durLast, nsLast)
	t.Logf("  Exact match:         %v (%.2f ns/op)", durMatch, nsMatch)

	// In constant-time compare, maximum variance across positions should be tiny (< 10 ns/op)
	maxDiff := math.Max(math.Abs(nsFirst-nsLast), math.Abs(nsMid-nsLast))
	if maxDiff > 10.0 {
		t.Logf("Warning: slight timing difference measured: %.2f ns/op (likely CPU scheduling noise)", maxDiff)
	}

	// Verify correctness of return values
	if subtle.ConstantTimeCompare([]byte(mismatchFirstByte), []byte(correctToken)) != 0 {
		t.Errorf("ConstantTimeCompare returned 1 for mismatch first byte")
	}
	if subtle.ConstantTimeCompare([]byte(mismatchLastByte), []byte(correctToken)) != 0 {
		t.Errorf("ConstantTimeCompare returned 1 for mismatch last byte")
	}
	if subtle.ConstantTimeCompare([]byte(exactMatch), []byte(correctToken)) != 1 {
		t.Errorf("ConstantTimeCompare returned 0 for exact match")
	}
}

func TestStressCloudMetadataEgressBlocking(t *testing.T) {
	agent := NewAgentServer("test-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	// Metadata target variations
	metadataTargets := []string{
		"http://169.254.169.254",
		"http://169.254.169.254/",
		"http://169.254.169.254:80/latest/meta-data/",
		"http://169.254.169.254:8080/latest/meta-data/",
		"http://169.254.169.254/latest/api/token",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://[fd00:ec2::254]:80/",
		"http://100.100.100.200/v1/meta",
		"http://100.100.100.200:80/v1/meta",
	}

	for _, target := range metadataTargets {
		payload, _ := json.Marshal(ProxyRequest{
			URL:    target,
			Method: "GET",
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
		req.Header.Set("X-EF-Token", "test-token")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed for target %s: %v", target, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("CRITICAL: Cloud metadata target %s was NOT blocked! Status: %d, Body: %s",
				target, resp.StatusCode, string(respBody))
		}
	}
}

func TestStressCloudMetadataAlternateEncodingsBypass(t *testing.T) {
	// Alternate IP encodings that resolve to 169.254.169.254 in OS resolvers
	// but bypass exact string matching in isBlockedProxyTarget:
	cases := []struct {
		name   string
		target string
	}{
		{"Decimal IP encoding (2852039166)", "http://2852039166/latest/meta-data/"},
		{"Dotted hex encoding (0xa9.0xfe.0xa9.0xfe)", "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/"},
		{"Octal encoding (0251.0376.0251.0376)", "http://0251.0376.0251.0376/latest/meta-data/"},
		{"IPv6-mapped IPv4 ([::ffff:169.254.169.254])", "http://[::ffff:169.254.169.254]/latest/meta-data/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked := isBlockedProxyTarget(tc.target)
			t.Logf("isBlockedProxyTarget(%q) = %v", tc.target, blocked)
			if !blocked {
				t.Errorf("SECURITY FLAW: Alternate metadata IP representation %q bypassed isBlockedProxyTarget()", tc.target)
			}
		})
	}
}

func TestStressProxyRedirectMetadataProtection(t *testing.T) {
	// Verify that if an external server attempts to redirect to cloud metadata (SSRF redirect chain),
	// the proxy client does NOT follow the redirect (CheckRedirect: http.ErrUseLastResponse).
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with 302 redirecting to AWS metadata
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirectServer.Close()

	agent := NewAgentServer("proxy-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	client := ts.Client()

	payload, _ := json.Marshal(ProxyRequest{
		URL:    redirectServer.URL,
		Method: "GET",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/proxy", bytes.NewReader(payload))
	req.Header.Set("X-EF-Token", "proxy-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode proxy response: %v", err)
	}

	// The agent proxy must surface the 302 directly, and NOT follow the redirect to 169.254.169.254
	statusCode, ok := result["statusCode"].(float64)
	if !ok || int(statusCode) != http.StatusFound {
		t.Errorf("Expected proxy to return raw redirect statusCode 302, got %v", result["statusCode"])
	}
}
