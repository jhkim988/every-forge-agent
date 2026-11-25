package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCronHardening_QuotedHashInCommandPreserved(t *testing.T) {
	raw := "0 9 * * 1-5 /usr/bin/notify.sh \"deploy # 42 done\" # Real comment\n" +
		"*/5 * * * * echo 'tag #1' >> /tmp/out.log\n"
	jobs := parseCrontab(raw)
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(jobs))
	}
	if jobs[0].Command != `/usr/bin/notify.sh "deploy # 42 done"` || jobs[0].Comment != "Real comment" {
		t.Errorf("job 0 broken by quoted #: %+v", jobs[0])
	}
	if jobs[1].Command != `echo 'tag #1' >> /tmp/out.log` || jobs[1].Comment != "" {
		t.Errorf("job 1 broken by single-quoted #: %+v", jobs[1])
	}
}

func TestCronHardening_StaleLineIDDoesNotOverwriteEnvVar(t *testing.T) {
	existing := "# Header\nMAILTO=ops@example.com\n0 9 * * * /backup.sh\n"

	// line_2 is MAILTO=..., NOT a cron job -> checked update MUST reject!
	_, err := updateCrontabContentChecked(existing, CronJob{
		ID:       "line_2",
		Schedule: "* * * * *",
		Command:  "/clobber.sh",
		Enabled:  true,
	})
	if err == nil {
		t.Fatal("expected error when attempting to overwrite non-cron line_2 (MAILTO=...)")
	}

	// Out-of-range stale line_9 -> MUST reject instead of silently appending duplicate!
	_, errOOB := updateCrontabContentChecked(existing, CronJob{
		ID:       "line_9",
		Schedule: "* * * * *",
		Command:  "/stale.sh",
		Enabled:  true,
	})
	if errOOB == nil {
		t.Fatal("expected error when attempting to update out-of-bounds stale line_9")
	}

	// HTTP integration: stale ID returns 409 Conflict
	agent := NewAgentServer("tok", false)
	agent.CrontabReadFunc = func() (string, error) { return existing, nil }
	agent.CrontabWriteFunc = func(c string) error {
		t.Fatalf("CrontabWriteFunc must not be called on stale ID! got: %s", c)
		return nil
	}
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	body, _ := json.Marshal(CronSaveRequest{
		ID:       "line_2",
		Schedule: "* * * * *",
		Command:  "/clobber.sh",
		Enabled:  true,
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", bytes.NewReader(body))
	req.Header.Set("X-EF-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for stale line_2 save, got %d", resp.StatusCode)
	}
}

func TestCronHardening_OversizedRequestBodyReturns413(t *testing.T) {
	agent := NewAgentServer("tok", false)
	ts := httptest.NewServer(agent.Routes())
	defer ts.Close()

	huge := `{"schedule":"* * * * *","command":"echo ` + strings.Repeat("A", 128<<10) + `"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/cron/save", strings.NewReader(huge))
	req.Header.Set("X-EF-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized cron save payload, got %d", resp.StatusCode)
	}
}

func TestCronHardening_WindowsScheduleTranslationAndUniqueID(t *testing.T) {
	// 1. Empty Windows task name rejected by validator, while auto-ID helper creates EF_<hex>
	if _, err := validateWindowsTaskName(""); err == nil {
		t.Error("validateWindowsTaskName(\"\") must return error")
	}
	if _, err := validateWindowsTaskName("EF_"); err == nil {
		t.Error("validateWindowsTaskName(\"EF_\") must return error")
	}
	gen1, err1 := resolveOrGenerateWindowsTaskName("")
	gen2, err2 := resolveOrGenerateWindowsTaskName("")
	if err1 != nil || err2 != nil || gen1 == gen2 || !strings.HasPrefix(gen1, "EF_") {
		t.Fatalf("expected unique EF_ task names, got %q, %q (%v, %v)", gen1, gen2, err1, err2)
	}

	// 2. Schedule -> schtasks args translation
	cases := []struct {
		schedule string
		wantArgs []string
		wantErr  bool
	}{
		{"*/15 * * * *", []string{"/SC", "MINUTE", "/MO", "15"}, false},
		{"* * * * *", []string{"/SC", "MINUTE", "/MO", "1"}, false},
		{"0 */4 * * *", []string{"/SC", "HOURLY", "/MO", "4", "/ST", "00:00"}, false},
		{"30 14 * * *", []string{"/SC", "DAILY", "/ST", "14:30"}, false},
		{"0 9 * * 1-5", []string{"/SC", "WEEKLY", "/D", "MON,TUE,WED,THU,FRI", "/ST", "09:00"}, false},
		{"15 3 1 * *", []string{"/SC", "MONTHLY", "/D", "1", "/ST", "03:15"}, false},
		{"@reboot", []string{"/SC", "ONSTART"}, false},
		{"@daily", []string{"/SC", "DAILY", "/ST", "00:00"}, false},
		{"5,10,15 0-23/2 1-10 1-6 1-5", nil, true}, // Unrepresentable in schtasks -> explicit error, NEVER silent 09:00!
	}

	for _, tc := range cases {
		args, err := buildWindowsSchtasksCreateArgs("EF_Test", CronSaveRequest{
			Schedule: tc.schedule,
			Command:  `C:\run.bat`,
		})
		if (err != nil) != tc.wantErr {
			t.Errorf("schedule %q error = %v, wantErr %v", tc.schedule, err, tc.wantErr)
			continue
		}
		if !tc.wantErr {
			joined := strings.Join(args, " ")
			for _, sub := range tc.wantArgs {
				if !strings.Contains(joined, sub) {
					t.Errorf("schedule %q args %q missing expected %q", tc.schedule, joined, sub)
				}
			}
		}
	}

	// 3. Verbose schtasks CSV schedule reconstruction
	// 25+ columns matching Windows `schtasks /Query /FO CSV /V /NH`
	verboseRow := []string{
		"MYPC", `\EF_Every15`, "2026-11-25 12:15:00", "Ready", "Interactive",
		"N/A", "0", "User", `C:\sync.bat`, `C:\`, "Sync comment",
		"Enabled", "Disabled", "Disabled", "User", "No", "72:00:00", "Normal",
		"Minute", "12:00:00", "2026-11-25", "N/A", "N/A", "N/A", "0 Hour(s), 15 Minute(s)",
	}
	if got := inferCronFromSchtasksRecord(verboseRow); got != "*/15 * * * *" {
		t.Errorf("expected */15 * * * * from verbose CSV row, got %q", got)
	}
}
