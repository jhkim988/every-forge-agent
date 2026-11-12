package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIsValidCronSchedule(t *testing.T) {
	validCases := []string{
		"0 9 * * 1-5",
		"*/15 * * * *",
		"0 0 1 1 *",
		"5,10,15 0-23/2 1-31 * *",
		"30 4 1,15 * 5",
		"0 0 * * SUN",
		"0 12 * JAN-DEC *",
		"@reboot",
		"@hourly",
		"@daily",
		"@midnight",
		"@weekly",
		"@monthly",
		"@yearly",
		"@annually",
	}

	for _, tc := range validCases {
		if !isValidCronSchedule(tc) {
			t.Errorf("Expected valid schedule %q to pass validation, but it failed", tc)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		"* * * *",         // 4 fields
		"* * * * * *",     // 6 fields
		"60 * * * *",       // minute > 59
		"-1 * * * *",       // minute < 0
		"* 24 * * *",       // hour > 23
		"* * 0 * *",        // dom < 1
		"* * 32 * *",       // dom > 31
		"* * * 0 *",        // month < 1
		"* * * 13 *",       // month > 12
		"* * * * 8",        // dow > 7
		"*/0 * * * *",      // step == 0
		"* * * * *; rm -rf /",
		"0 0 * * * && curl evil.com",
		"0 9 * * 1\n* * * * *",
		"invalid-schedule",
		"@hourly_invalid",
	}

	for _, tc := range invalidCases {
		if isValidCronSchedule(tc) {
			t.Errorf("Expected invalid schedule %q to fail validation, but it passed", tc)
		}
	}
}

func TestParseCrontab(t *testing.T) {
	sample := `# User crontab
MAILTO=jinhan@example.com
PATH=/usr/local/bin:/usr/bin:/bin

0 9 * * 1-5 /usr/bin/backup.sh # Daily morning backup
# 30 2 * * * /usr/bin/cleanup.sh # Nightly cleanup
@hourly /usr/local/bin/sync.sh
*/10 * * * * curl -s https://example.com/ping
`

	jobs := parseCrontab(sample)
	if len(jobs) != 4 {
		t.Fatalf("Expected 4 jobs parsed, got %d", len(jobs))
	}

	// Job 1: Active 5-field with comment
	j1 := jobs[0]
	if j1.ID != "line_5" || j1.Schedule != "0 9 * * 1-5" || j1.Command != "/usr/bin/backup.sh" || j1.Comment != "Daily morning backup" || !j1.Enabled {
		t.Errorf("Unexpected job 1: %+v", j1)
	}

	// Job 2: Disabled with comment
	j2 := jobs[1]
	if j2.ID != "line_6" || j2.Schedule != "30 2 * * *" || j2.Command != "/usr/bin/cleanup.sh" || j2.Comment != "Nightly cleanup" || j2.Enabled {
		t.Errorf("Unexpected job 2 (disabled): %+v", j2)
	}

	// Job 3: Macro @hourly
	j3 := jobs[2]
	if j3.ID != "line_7" || j3.Schedule != "@hourly" || j3.Command != "/usr/local/bin/sync.sh" || !j3.Enabled {
		t.Errorf("Unexpected job 3 (macro): %+v", j3)
	}

	// Job 4: No comment
	j4 := jobs[3]
	if j4.ID != "line_8" || j4.Schedule != "*/10 * * * *" || j4.Command != "curl -s https://example.com/ping" || j4.Comment != "" || !j4.Enabled {
		t.Errorf("Unexpected job 4: %+v", j4)
	}

	// Empty input yields empty slice
	if emptyJobs := parseCrontab(""); len(emptyJobs) != 0 {
		t.Errorf("Expected 0 jobs from empty input, got %d", len(emptyJobs))
	}
	if commentOnly := parseCrontab("# Just a comment\n# Another comment\n"); len(commentOnly) != 0 {
		t.Errorf("Expected 0 jobs from comment-only input, got %d", len(commentOnly))
	}
}

func TestFormatCronLine(t *testing.T) {
	activeWithComment := CronJob{
		Schedule: "0 9 * * 1-5",
		Command:  "/bin/backup.sh",
		Comment:  "test comment",
		Enabled:  true,
	}
	if got := formatCronLine(activeWithComment); got != "0 9 * * 1-5 /bin/backup.sh # test comment" {
		t.Errorf("Unexpected formatted active line: %q", got)
	}

	disabledWithComment := CronJob{
		Schedule: "0 9 * * 1-5",
		Command:  "/bin/backup.sh",
		Comment:  "test comment",
		Enabled:  false,
	}
	if got := formatCronLine(disabledWithComment); got != "# 0 9 * * 1-5 /bin/backup.sh # test comment" {
		t.Errorf("Unexpected formatted disabled line: %q", got)
	}

	activeNoComment := CronJob{
		Schedule: "@daily",
		Command:  "/bin/sync.sh",
		Enabled:  true,
	}
	if got := formatCronLine(activeNoComment); got != "@daily /bin/sync.sh" {
		t.Errorf("Unexpected formatted line without comment: %q", got)
	}
}

func TestUpdateCrontabContent(t *testing.T) {
	sample := `# Header
MAILTO=admin@example.com
0 9 * * 1-5 /backup.sh # Backup
# 30 2 * * * /cleanup.sh # Clean
`

	// Toggle line_4 from disabled to enabled
	updated := updateCrontabContent(sample, CronJob{
		ID:       "line_4",
		Schedule: "30 2 * * *",
		Command:  "/cleanup.sh",
		Comment:  "Clean",
		Enabled:  true,
	})

	if !strings.Contains(updated, "30 2 * * * /cleanup.sh # Clean") {
		t.Errorf("Expected enabled line in updated crontab, got: %s", updated)
	}
	if strings.Contains(updated, "# 30 2 * * *") {
		t.Errorf("Disabled line was not replaced in updated crontab: %s", updated)
	}
	if !strings.HasPrefix(updated, "# Header\nMAILTO=admin@example.com") {
		t.Errorf("Headers were not preserved: %s", updated)
	}
	if !strings.HasSuffix(updated, "\n") {
		t.Errorf("Crontab output must end with trailing newline")
	}

	// Append new job
	appended := updateCrontabContent(updated, CronJob{
		ID:       "",
		Schedule: "@hourly",
		Command:  "/sync.sh",
		Enabled:  true,
	})
	if !strings.Contains(appended, "@hourly /sync.sh") {
		t.Errorf("Appended job missing: %s", appended)
	}
}

func TestDeleteCrontabContent(t *testing.T) {
	sample := `# Header
MAILTO=admin@example.com
0 9 * * 1-5 /backup.sh # Backup
# 30 2 * * * /cleanup.sh # Clean
`

	// Delete line 3 (the backup job)
	res, err := deleteCrontabContent(sample, "line_3")
	if err != nil {
		t.Fatalf("deleteCrontabContent failed: %v", err)
	}

	if strings.Contains(res, "/backup.sh") {
		t.Errorf("Deleted job still present in crontab: %s", res)
	}
	if !strings.Contains(res, "MAILTO=admin@example.com") {
		t.Errorf("Header was removed accidentally: %s", res)
	}
	if !strings.Contains(res, "# 30 2 * * * /cleanup.sh # Clean") {
		t.Errorf("Other jobs were modified accidentally: %s", res)
	}

	// Error when ID not found
	_, errNotFound := deleteCrontabContent(sample, "line_99")
	if errNotFound == nil {
		t.Errorf("Expected error when deleting non-existent line, got nil")
	}

	// Deleting only remaining job yields empty string
	singleJob := "0 9 * * 1-5 /backup.sh\n"
	emptyRes, errSingle := deleteCrontabContent(singleJob, "line_1")
	if errSingle != nil {
		t.Fatalf("Failed to delete only job: %v", errSingle)
	}
	if emptyRes != "" {
		t.Errorf("Expected empty string when deleting all jobs, got %q", emptyRes)
	}
}

func TestValidateCronJobInput(t *testing.T) {
	valid := CronSaveRequest{
		Schedule: "0 9 * * 1-5",
		Command:  "/bin/sh /path/to/script.sh",
		Comment:  "Safe backup",
		Enabled:  true,
	}
	if err := validateCronJobInput(valid); err != nil {
		t.Errorf("Expected valid request to pass, got error: %v", err)
	}

	// Newline injection in command
	injCmd := valid
	injCmd.Command = "/bin/sh\n* * * * * /evil.sh"
	if err := validateCronJobInput(injCmd); err == nil {
		t.Errorf("Expected error for command with newline, got nil")
	}

	// Carriage return injection in command
	injCr := valid
	injCr.Command = "/bin/sh\r\n* * * * * /evil.sh"
	if err := validateCronJobInput(injCr); err == nil {
		t.Errorf("Expected error for command with carriage return, got nil")
	}

	// Null byte injection in command
	injNull := valid
	injNull.Command = "/bin/sh\x00evil"
	if err := validateCronJobInput(injNull); err == nil {
		t.Errorf("Expected error for command with null byte, got nil")
	}

	// Newline injection in schedule
	injSched := valid
	injSched.Schedule = "0 9 * * 1\n* * * * *"
	if err := validateCronJobInput(injSched); err == nil {
		t.Errorf("Expected error for schedule with newline, got nil")
	}

	// Newline injection in comment
	injComment := valid
	injComment.Comment = "safe\n* * * * * evil"
	if err := validateCronJobInput(injComment); err == nil {
		t.Errorf("Expected error for comment with newline, got nil")
	}

	// Empty command
	emptyCmd := valid
	emptyCmd.Command = "   "
	if err := validateCronJobInput(emptyCmd); err == nil {
		t.Errorf("Expected error for empty command, got nil")
	}

	// Invalid schedule
	badSched := valid
	badSched.Schedule = "not a schedule"
	if err := validateCronJobInput(badSched); err == nil {
		t.Errorf("Expected error for invalid schedule, got nil")
	}
}

func TestWindowsTaskHelpers(t *testing.T) {
	// Task name prefixing and validation
	name, err := validateWindowsTaskName("BackupJob")
	if err != nil || name != "EF_BackupJob" {
		t.Errorf("Expected EF_BackupJob, got %s (err: %v)", name, err)
	}

	name2, err2 := validateWindowsTaskName("EF_Sync_123")
	if err2 != nil || name2 != "EF_Sync_123" {
		t.Errorf("Expected EF_Sync_123, got %s (err: %v)", name2, err2)
	}

	// Invalid task name characters
	invalidNames := []string{
		"Job; calc.exe",
		"Job/path",
		"Job & whoami",
		"Job\"evil",
	}
	for _, inv := range invalidNames {
		if _, err := validateWindowsTaskName(inv); err == nil {
			t.Errorf("Expected error for invalid task name %q, got nil", inv)
		}
	}

	// CSV parsing
	csvSample := `"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment"` + "\n" +
		`"MYPC","\\EF_Backup","2026-09-10 09:00:00","Ready","Interactive","N/A","0","User","C:\backup.bat","C:\","Daily backup"` + "\n" +
		`"MYPC","\\Microsoft\\Windows\\Defrag","N/A","Ready","Interactive","N/A","0","System","defrag.exe","C:\","OS Defrag"` + "\n"

	jobs := parseSchtasksCSV(csvSample)
	if len(jobs) != 1 {
		t.Fatalf("Expected only 1 EF_ job parsed from CSV, got %d", len(jobs))
	}
	if jobs[0].ID != "EF_Backup" || !jobs[0].Enabled || jobs[0].Command != `C:\backup.bat` {
		t.Errorf("Unexpected parsed Windows task: %+v", jobs[0])
	}
}

func TestCronEndpointsIntegration(t *testing.T) {
	agent := NewAgentServer("cron-secret-token", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	// 1. Auth required for /api/cron/list
	reqUnauth, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cron/list", nil)
	respUnauth, err := http.DefaultClient.Do(reqUnauth)
	if err != nil {
		t.Fatalf("unauth request failed: %v", err)
	}
	respUnauth.Body.Close()
	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated /api/cron/list, got %d", respUnauth.StatusCode)
	}

	// 2. Method Not Allowed for POST on /api/cron/list
	reqBadMethod, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/list", nil)
	reqBadMethod.Header.Set("X-EF-Token", "cron-secret-token")
	respBadMethod, _ := http.DefaultClient.Do(reqBadMethod)
	respBadMethod.Body.Close()
	if respBadMethod.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for POST /api/cron/list, got %d", respBadMethod.StatusCode)
	}

	// 3. Method Not Allowed for GET on /api/cron/save
	reqSaveGet, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cron/save", nil)
	reqSaveGet.Header.Set("X-EF-Token", "cron-secret-token")
	respSaveGet, _ := http.DefaultClient.Do(reqSaveGet)
	respSaveGet.Body.Close()
	if respSaveGet.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET /api/cron/save, got %d", respSaveGet.StatusCode)
	}

	// 4. Method Not Allowed for GET on /api/cron/delete
	reqDelGet, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cron/delete", nil)
	reqDelGet.Header.Set("X-EF-Token", "cron-secret-token")
	respDelGet, _ := http.DefaultClient.Do(reqDelGet)
	respDelGet.Body.Close()
	if respDelGet.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET /api/cron/delete, got %d", respDelGet.StatusCode)
	}

	// 5. Validation error on /api/cron/save (missing command)
	badSaveBody, _ := json.Marshal(CronSaveRequest{Schedule: "0 9 * * *"})
	reqBadSave, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader(badSaveBody))
	reqBadSave.Header.Set("X-EF-Token", "cron-secret-token")
	respBadSave, _ := http.DefaultClient.Do(reqBadSave)
	respBadSave.Body.Close()
	if respBadSave.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for save with missing command, got %d", respBadSave.StatusCode)
	}

	// 6. Validation error on /api/cron/save (newline injection)
	injSaveBody, _ := json.Marshal(CronSaveRequest{
		Schedule: "0 9 * * *",
		Command:  "echo safe\n* * * * * /evil.sh",
	})
	reqInjSave, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader(injSaveBody))
	reqInjSave.Header.Set("X-EF-Token", "cron-secret-token")
	respInjSave, _ := http.DefaultClient.Do(reqInjSave)
	respInjSave.Body.Close()
	if respInjSave.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for command with newline injection, got %d", respInjSave.StatusCode)
	}

	// 7. Validation error on /api/cron/delete (missing ID)
	reqDelNoId, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/delete", bytes.NewReader([]byte("{}")))
	reqDelNoId.Header.Set("X-EF-Token", "cron-secret-token")
	respDelNoId, _ := http.DefaultClient.Do(reqDelNoId)
	respDelNoId.Body.Close()
	if respDelNoId.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for delete with missing ID, got %d", respDelNoId.StatusCode)
	}

	// 8. Loopback Host header guard
	reqBadHost, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cron/list", nil)
	reqBadHost.Header.Set("X-EF-Token", "cron-secret-token")
	reqBadHost.Host = "attacker.evil.com"
	respBadHost, _ := http.DefaultClient.Do(reqBadHost)
	respBadHost.Body.Close()
	if respBadHost.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for non-loopback Host header on /api/cron/list, got %d", respBadHost.StatusCode)
	}
}

func TestCronSaveRejectsUnescapedPercent(t *testing.T) {
	agent := NewAgentServer("test-token-1234", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	// 1. Unescaped % acts as newline in cron daemon -> should be rejected
	body := `{"schedule":"* * * * *","command":"date +%Y-%m-%d >> /tmp/test.log","comment":"bad percent"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", strings.NewReader(body))
	req.Header.Set("X-EF-Token", "test-token-1234")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for unescaped %% in cron command, got %d", resp.StatusCode)
	}

	// 2. Escaped \% should pass validation
	escapedBody := `{"schedule":"* * * * *","command":"date +\\%Y-\\%m-\\%d >> /tmp/test.log","comment":"escaped percent"}`
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", strings.NewReader(escapedBody))
	req2.Header.Set("X-EF-Token", "test-token-1234")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for escaped \\%% in cron command, got %d", resp2.StatusCode)
	}
}

func TestCronConcurrentSaveRace(t *testing.T) {
	agent := NewAgentServer("test-token-1234", false)
	var storeMu sync.Mutex
	crontabContent := ""

	agent.CrontabReadFunc = func() (string, error) {
		storeMu.Lock()
		defer storeMu.Unlock()
		return crontabContent, nil
	}
	agent.CrontabWriteFunc = func(content string) error {
		time.Sleep(2 * time.Millisecond) // amplify race window
		storeMu.Lock()
		defer storeMu.Unlock()
		crontabContent = content
		return nil
	}

	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"schedule":"0 * * * *","command":"/usr/bin/echo job-%d","comment":"job-%d"}`, idx, idx)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", strings.NewReader(body))
			req.Header.Set("X-EF-Token", "test-token-1234")
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("worker %d failed: %v", idx, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("worker %d failed with status %d", idx, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()

	jobs := parseCrontab(crontabContent)
	if len(jobs) != workers {
		t.Fatalf("expected %d cron jobs after concurrent saves, got %d", workers, len(jobs))
	}
}
