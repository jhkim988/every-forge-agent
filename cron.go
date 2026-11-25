package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	cronExecTimeout  = 5 * time.Second
	maxCronBodyBytes = 64 << 10 // 64 KB cap for cron JSON payloads
)

var (
	schtasksRepeatMinRegex  = regexp.MustCompile(`(?i)(\d+)\s*Minute`)
	schtasksRepeatHourRegex = regexp.MustCompile(`(?i)(\d+)\s*Hour`)
	schtasksTimeRegex       = regexp.MustCompile(`(\d{1,2}):(\d{2})(?::\d{2})?`)
)

type CronJob struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Comment  string `json:"comment,omitempty"`
	Enabled  bool   `json:"enabled"`
	Raw      string `json:"raw,omitempty"`
}

type CronListResponse struct {
	Status string    `json:"status"`
	OS     string    `json:"os"`
	Raw    string    `json:"raw"`
	Jobs   []CronJob `json:"jobs"`
}

type CronSaveRequest struct {
	ID       string `json:"id,omitempty"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Comment  string `json:"comment,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type CronDeleteRequest struct {
	ID string `json:"id"`
}

func parseCrontab(raw string) []CronJob {
	var jobs []CronJob
	lines := strings.Split(raw, "\n")
	for lineIdx, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			continue
		}

		enabled := true
		content := trimmed

		if strings.HasPrefix(content, "#") {
			afterHash := strings.TrimSpace(strings.TrimPrefix(content, "#"))
			if !isCronLine(afterHash) {
				continue
			}
			enabled = false
			content = afterHash
		} else {
			if strings.Contains(content, "=") && !strings.Contains(strings.Split(content, "=")[0], " ") {
				continue
			}
			if !isCronLine(content) {
				continue
			}
		}

		job := parseCronLineContent(content, enabled, rawLine, lineIdx+1)
		jobs = append(jobs, job)
	}
	return jobs
}

func isCronLine(s string) bool {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return false
	}
	if validMacroRegex.MatchString(fields[0]) {
		return true
	}
	if len(fields) >= 6 && isValidCronSchedule(strings.Join(fields[0:5], " ")) {
		return true
	}
	return false
}

func parseCronLineContent(s string, enabled bool, rawLine string, lineNum int) CronJob {
	fields := strings.Fields(s)
	var schedule string
	var rest string

	if validMacroRegex.MatchString(fields[0]) {
		schedule = fields[0]
		idx := strings.Index(s, fields[0]) + len(fields[0])
		rest = strings.TrimSpace(s[idx:])
	} else {
		schedule = strings.Join(fields[0:5], " ")
		cur := 0
		for i := 0; i < 5; i++ {
			fieldIdx := strings.Index(s[cur:], fields[i])
			cur += fieldIdx + len(fields[i])
		}
		rest = strings.TrimSpace(s[cur:])
	}

	command, comment := splitCronCommandAndComment(rest)

	return CronJob{
		ID:       fmt.Sprintf("line_%d", lineNum),
		Schedule: schedule,
		Command:  command,
		Comment:  comment,
		Enabled:  enabled,
		Raw:      rawLine,
	}
}

// splitCronCommandAndComment splits a crontab command and trailing inline comment
// on ` # ` (or trailing ` #`), ignoring `#` characters inside single/double quotes.
func splitCronCommandAndComment(rest string) (string, string) {
	if strings.HasPrefix(rest, "#") {
		return "", strings.TrimSpace(strings.TrimPrefix(rest, "#"))
	}
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && !inSingle {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && ch == '#' && i > 0 && rest[i-1] == ' ' {
			if i+1 == len(rest) || rest[i+1] == ' ' {
				cmd := strings.TrimSpace(rest[:i])
				cmt := strings.TrimSpace(rest[i+1:])
				return cmd, cmt
			}
		}
	}
	return strings.TrimSpace(rest), ""
}

func formatCronLine(job CronJob) string {
	line := job.Schedule + " " + job.Command
	if job.Comment != "" {
		line += " # " + job.Comment
	}
	if !job.Enabled {
		line = "# " + line
	}
	return line
}

func updateCrontabContentChecked(existingRaw string, job CronJob) (string, error) {
	lines := strings.Split(existingRaw, "\n")
	newLine := formatCronLine(job)

	if strings.TrimSpace(job.ID) != "" {
		existingJobs := parseCrontab(existingRaw)
		found := false
		for _, j := range existingJobs {
			if j.ID == job.ID {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("cron job %q not found or crontab changed externally; refresh and retry", job.ID)
		}

		lineNum := -1
		if strings.HasPrefix(job.ID, "line_") {
			if n, err := strconv.Atoi(strings.TrimPrefix(job.ID, "line_")); err == nil {
				lineNum = n - 1
			}
		}
		if lineNum < 0 || lineNum >= len(lines) {
			return "", fmt.Errorf("cron job %q out of range; refresh and retry", job.ID)
		}
		lines[lineNum] = newLine
	} else {
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(lines, newLine)
	}

	result := strings.Join(lines, "\n")
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return result, nil
}

func updateCrontabContent(existingRaw string, job CronJob) string {
	updated, err := updateCrontabContentChecked(existingRaw, job)
	if err == nil {
		return updated
	}
	// Preserve legacy fallback behavior for direct unit callers with non-matching IDs
	lines := strings.Split(existingRaw, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, formatCronLine(job))
	return strings.Join(lines, "\n") + "\n"
}

func deleteCrontabContent(existingRaw string, id string) (string, error) {
	if strings.TrimSpace(existingRaw) == "" {
		return "", errors.New("cron job not found with id: " + id)
	}

	jobs := parseCrontab(existingRaw)
	var targetJob *CronJob
	for i := range jobs {
		if jobs[i].ID == id {
			targetJob = &jobs[i]
			break
		}
	}
	if targetJob == nil {
		return "", errors.New("cron job not found with id: " + id)
	}

	lines := strings.Split(existingRaw, "\n")
	lineNum := -1
	if strings.HasPrefix(id, "line_") {
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "line_")); err == nil {
			lineNum = n - 1
		}
	}

	if lineNum < 0 || lineNum >= len(lines) {
		return "", errors.New("cron job not found with id: " + id)
	}

	lines = append(lines[:lineNum], lines[lineNum+1:]...)

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	if len(lines) == 0 {
		return "", nil
	}

	return strings.Join(lines, "\n") + "\n", nil
}

func readUserCrontab() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cronExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		combined := strings.ToLower(stdout.String() + stderr.String())
		if strings.Contains(combined, "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l failed: %v: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func writeUserCrontab(content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cronExecTimeout)
	defer cancel()

	if strings.TrimSpace(content) == "" {
		cmd := exec.CommandContext(ctx, "crontab", "-r")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if strings.Contains(strings.ToLower(stderr.String()), "no crontab for") {
				return nil
			}
			return fmt.Errorf("crontab -r failed: %v: %s", err, stderr.String())
		}
		return nil
	}

	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab write failed: %v: %s", err, stderr.String())
	}
	return nil
}

func readWindowsTasks() ([]CronJob, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cronExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "schtasks", "/Query", "/FO", "CSV", "/V", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("schtasks query failed: %v", err)
	}

	raw := string(out)
	jobs := parseSchtasksCSV(raw)
	return jobs, raw, nil
}

func parseSchtasksCSV(raw string) []CronJob {
	var jobs []CronJob
	r := csv.NewReader(strings.NewReader(raw))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return jobs
	}

	for _, rec := range records {
		if len(rec) < 5 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rec[0]), "HostName") && strings.EqualFold(strings.TrimSpace(rec[1]), "TaskName") {
			continue
		}
		taskName := strings.Trim(rec[1], "\\")
		if !strings.HasPrefix(taskName, "EF_") {
			continue
		}

		status := ""
		taskToRun := ""
		comment := ""
		if len(rec) > 10 {
			comment = rec[10]
		}
		if len(rec) > 3 {
			status = rec[3]
		}
		for _, col := range rec {
			if strings.Contains(col, ".exe") || strings.Contains(col, ".bat") || strings.Contains(col, ".cmd") || strings.Contains(col, ".ps1") {
				taskToRun = col
				break
			}
		}
		if taskToRun == "" && len(rec) > 8 {
			taskToRun = rec[8]
		}

		enabled := !strings.EqualFold(status, "Disabled")

		jobs = append(jobs, CronJob{
			ID:       taskName,
			Schedule: inferCronFromSchtasksRecord(rec),
			Command:  taskToRun,
			Comment:  comment,
			Enabled:  enabled,
			Raw:      strings.Join(rec, ","),
		})
	}
	return jobs
}

func inferCronFromSchtasksRecord(rec []string) string {
	extractHM := func(s string) (int, int, bool) {
		m := schtasksTimeRegex.FindStringSubmatch(strings.TrimSpace(s))
		if len(m) < 3 {
			return 0, 0, false
		}
		h, err1 := strconv.Atoi(m[1])
		min, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil || h < 0 || h > 23 || min < 0 || min > 59 {
			return 0, 0, false
		}
		return h, min, true
	}

	if len(rec) >= 25 {
		schedType := strings.ToLower(strings.TrimSpace(rec[18]))
		startTime := strings.TrimSpace(rec[19])
		daysCol := strings.ToUpper(strings.TrimSpace(rec[22]))
		repeatCol := strings.TrimSpace(rec[24])
		h, min, hasHM := extractHM(startTime)

		switch {
		case strings.Contains(schedType, "start up") || strings.Contains(schedType, "startup") || strings.Contains(schedType, "onstart"):
			return "@reboot"
		case strings.Contains(schedType, "minute"):
			if m := schtasksRepeatMinRegex.FindStringSubmatch(repeatCol); len(m) >= 2 {
				if n, err := strconv.Atoi(m[1]); err == nil && n > 1 && n <= 59 {
					return fmt.Sprintf("*/%d * * * *", n)
				}
			}
			return "* * * * *"
		case strings.Contains(schedType, "hourly"):
			step := 1
			if m := schtasksRepeatHourRegex.FindStringSubmatch(repeatCol); len(m) >= 2 {
				if n, err := strconv.Atoi(m[1]); err == nil && n >= 1 && n <= 23 {
					step = n
				}
			}
			if step == 1 && (!hasHM || min == 0) {
				return "@hourly"
			}
			if step == 1 {
				return fmt.Sprintf("%d * * * *", min)
			}
			return fmt.Sprintf("%d */%d * * *", min, step)
		case strings.Contains(schedType, "daily"):
			if hasHM {
				return fmt.Sprintf("%d %d * * *", min, h)
			}
			return "@daily"
		case strings.Contains(schedType, "weekly"):
			dow := "*"
			if daysCol != "" && daysCol != "N/A" {
				dow = daysCol
			}
			if hasHM {
				return fmt.Sprintf("%d %d * * %s", min, h, dow)
			}
			return "@weekly"
		case strings.Contains(schedType, "monthly"):
			dom := "1"
			if daysCol != "" && daysCol != "N/A" {
				if _, err := strconv.Atoi(daysCol); err == nil {
					dom = daysCol
				}
			}
			if hasHM {
				return fmt.Sprintf("%d %d %s * *", min, h, dom)
			}
			return "@monthly"
		}
	}

	if len(rec) > 2 {
		if h, min, ok := extractHM(rec[2]); ok {
			return fmt.Sprintf("%d %d * * *", min, h)
		}
	}
	return "* * * * *"
}

func resolveOrGenerateWindowsTaskName(id string) (string, error) {
	if strings.TrimSpace(id) == "" {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generate windows task id: %w", err)
		}
		return "EF_" + hex.EncodeToString(b), nil
	}
	return validateWindowsTaskName(id)
}

var winDowNames = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}

func cronDowToWindowsDays(dowField string) (string, bool) {
	seen := make(map[string]bool)
	var ordered []string
	addDay := func(idx int) {
		name := winDowNames[idx%7]
		if !seen[name] {
			seen[name] = true
			ordered = append(ordered, name)
		}
	}
	parseDay := func(tok string) (int, bool) {
		up := strings.ToUpper(strings.TrimSpace(tok))
		for i, name := range winDowNames {
			if up == name {
				return i, true
			}
		}
		n, err := strconv.Atoi(up)
		if err != nil || n < 0 || n > 7 {
			return 0, false
		}
		return n % 7, true
	}

	for _, part := range strings.Split(dowField, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, "/") {
			return "", false
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return "", false
			}
			start, ok1 := parseDay(bounds[0])
			end, ok2 := parseDay(bounds[1])
			if !ok1 || !ok2 {
				return "", false
			}
			// Preserve raw numeric ordering for ranges like 1-5
			rawStart, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			rawEnd, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 == nil && err2 == nil {
				if rawStart > rawEnd {
					return "", false
				}
				for d := rawStart; d <= rawEnd; d++ {
					addDay(d)
				}
			} else {
				if start > end {
					return "", false
				}
				for d := start; d <= end; d++ {
					addDay(d)
				}
			}
		} else {
			d, ok := parseDay(part)
			if !ok {
				return "", false
			}
			addDay(d)
		}
	}
	if len(ordered) == 0 {
		return "", false
	}
	return strings.Join(ordered, ","), true
}

func buildWindowsSchtasksCreateArgs(taskName string, req CronSaveRequest) ([]string, error) {
	sched := strings.TrimSpace(req.Schedule)
	lower := strings.ToLower(sched)

	switch lower {
	case "@reboot":
		return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "ONSTART", "/F"}, nil
	case "@hourly":
		return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "HOURLY", "/MO", "1", "/ST", "00:00", "/F"}, nil
	case "@daily", "@midnight":
		return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "DAILY", "/ST", "00:00", "/F"}, nil
	case "@weekly":
		return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "WEEKLY", "/D", "SUN", "/ST", "00:00", "/F"}, nil
	case "@monthly":
		return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "MONTHLY", "/D", "1", "/ST", "00:00", "/F"}, nil
	case "@yearly", "@annually":
		return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "MONTHLY", "/M", "JAN", "/D", "1", "/ST", "00:00", "/F"}, nil
	}

	fields := strings.Fields(sched)
	if len(fields) != 5 {
		return nil, fmt.Errorf("unsupported schedule for Windows Task Scheduler: %q", req.Schedule)
	}
	minF, hourF, domF, monF, dowF := fields[0], fields[1], fields[2], fields[3], fields[4]

	// Minute-interval: "* * * * *" or "*/N * * * *"
	if hourF == "*" && domF == "*" && monF == "*" && dowF == "*" {
		if minF == "*" {
			return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "MINUTE", "/MO", "1", "/F"}, nil
		}
		if strings.HasPrefix(minF, "*/") {
			n, err := strconv.Atoi(strings.TrimPrefix(minF, "*/"))
			if err == nil && n >= 1 && n <= 59 {
				return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "MINUTE", "/MO", strconv.Itoa(n), "/F"}, nil
			}
		}
		if m, err := strconv.Atoi(minF); err == nil && m >= 0 && m <= 59 {
			return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "HOURLY", "/MO", "1", "/ST", fmt.Sprintf("00:%02d", m), "/F"}, nil
		}
	}

	// Hourly-interval: "M */N * * *"
	if m, errM := strconv.Atoi(minF); errM == nil && m >= 0 && m <= 59 && strings.HasPrefix(hourF, "*/") && domF == "*" && monF == "*" && dowF == "*" {
		n, errN := strconv.Atoi(strings.TrimPrefix(hourF, "*/"))
		if errN == nil && n >= 1 && n <= 23 {
			return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "HOURLY", "/MO", strconv.Itoa(n), "/ST", fmt.Sprintf("00:%02d", m), "/F"}, nil
		}
	}

	// Fixed minute + fixed hour
	m, errM := strconv.Atoi(minF)
	h, errH := strconv.Atoi(hourF)
	if errM == nil && errH == nil && m >= 0 && m <= 59 && h >= 0 && h <= 23 && monF == "*" {
		st := fmt.Sprintf("%02d:%02d", h, m)
		// Daily: M H * * *
		if domF == "*" && dowF == "*" {
			return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "DAILY", "/ST", st, "/F"}, nil
		}
		// Weekly: M H * * DOW
		if domF == "*" && dowF != "*" {
			if winDays, ok := cronDowToWindowsDays(dowF); ok {
				return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "WEEKLY", "/D", winDays, "/ST", st, "/F"}, nil
			}
		}
		// Monthly: M H DOM * *
		if domF != "*" && dowF == "*" {
			if dom, errD := strconv.Atoi(domF); errD == nil && dom >= 1 && dom <= 31 {
				return []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "MONTHLY", "/D", strconv.Itoa(dom), "/ST", st, "/F"}, nil
			}
		}
	}

	return nil, fmt.Errorf("unsupported schedule for Windows Task Scheduler: %q (use @reboot/@hourly/@daily/@weekly/@monthly or standard minute/hourly/daily/weekly/monthly 5-field syntax)", req.Schedule)
}

func saveWindowsTask(req CronSaveRequest) (string, error) {
	taskName, err := resolveOrGenerateWindowsTaskName(req.ID)
	if err != nil {
		return "", err
	}

	args, err := buildWindowsSchtasksCreateArgs(taskName, req)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cronExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "schtasks", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("schtasks /Create failed: %v: %s", err, string(out))
	}

	changeArg := "/ENABLE"
	if !req.Enabled {
		changeArg = "/DISABLE"
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), cronExecTimeout)
	defer cancel2()
	cmdChange := exec.CommandContext(ctx2, "schtasks", "/Change", "/TN", taskName, changeArg)
	_ = cmdChange.Run()

	return taskName, nil
}

func deleteWindowsTask(id string) error {
	taskName, err := validateWindowsTaskName(id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cronExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "schtasks", "/Delete", "/TN", taskName, "/F")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks /Delete failed: %v: %s", err, string(out))
	}
	return nil
}

func (a *AgentServer) handleCronList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var jobs []CronJob
	var raw string
	var err error

	if runtime.GOOS == "windows" {
		jobs, raw, err = readWindowsTasks()
	} else {
		raw, err = readUserCrontab()
		if err == nil {
			jobs = parseCrontab(raw)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	if jobs == nil {
		jobs = []CronJob{}
	}

	json.NewEncoder(w).Encode(CronListResponse{
		Status: "success",
		OS:     runtime.GOOS,
		Raw:    raw,
		Jobs:   jobs,
	})
}

func (a *AgentServer) handleCronSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCronBodyBytes)
	var req CronSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "request body exceeds maximum allowed size"})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "invalid JSON body: " + err.Error()})
		return
	}

	if err := validateCronJobInput(req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}

	a.cronMu.Lock()
	defer a.cronMu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	if runtime.GOOS == "windows" {
		taskName, err := saveWindowsTask(req)
		if err != nil {
			if strings.Contains(err.Error(), "unsupported schedule") || strings.Contains(err.Error(), "invalid task name") {
				w.WriteHeader(http.StatusBadRequest)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"job": CronJob{
				ID:       taskName,
				Schedule: req.Schedule,
				Command:  req.Command,
				Comment:  req.Comment,
				Enabled:  req.Enabled,
			},
		})
		return
	}

	readFn := a.CrontabReadFunc
	if readFn == nil {
		readFn = readUserCrontab
	}
	writeFn := a.CrontabWriteFunc
	if writeFn == nil {
		writeFn = writeUserCrontab
	}

	currentRaw, err := readFn()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}

	targetJob := CronJob{
		ID:       req.ID,
		Schedule: req.Schedule,
		Command:  req.Command,
		Comment:  req.Comment,
		Enabled:  req.Enabled,
	}

	newRaw, err := updateCrontabContentChecked(currentRaw, targetJob)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}
	if err := writeFn(newRaw); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}

	updatedJobs := parseCrontab(newRaw)
	var savedJob CronJob
	if len(updatedJobs) > 0 {
		savedJob = updatedJobs[len(updatedJobs)-1]
		if req.ID != "" {
			for _, j := range updatedJobs {
				if j.ID == req.ID {
					savedJob = j
					break
				}
			}
		}
	} else {
		savedJob = targetJob
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"job":    savedJob,
	})
}

func (a *AgentServer) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CronDeleteRequest
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxCronBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "request body exceeds maximum allowed size"})
				return
			}
		}
	}
	if req.ID == "" {
		req.ID = r.URL.Query().Get("id")
	}

	if strings.ContainsAny(req.ID, "\r\n\x00") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "invalid id parameter"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "missing id parameter"})
		return
	}

	a.cronMu.Lock()
	defer a.cronMu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	if runtime.GOOS == "windows" {
		if err := deleteWindowsTask(req.ID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"id":     req.ID,
		})
		return
	}

	readFn := a.CrontabReadFunc
	if readFn == nil {
		readFn = readUserCrontab
	}
	writeFn := a.CrontabWriteFunc
	if writeFn == nil {
		writeFn = writeUserCrontab
	}

	currentRaw, err := readFn()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}

	newRaw, err := deleteCrontabContent(currentRaw, req.ID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}

	if err := writeFn(newRaw); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"id":     req.ID,
	})
}
