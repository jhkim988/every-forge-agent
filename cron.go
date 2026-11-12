package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
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

	command := rest
	comment := ""

	if idx := strings.Index(rest, " # "); idx != -1 {
		command = strings.TrimSpace(rest[:idx])
		comment = strings.TrimSpace(rest[idx+3:])
	} else if strings.HasPrefix(rest, "#") {
		command = ""
		comment = strings.TrimSpace(strings.TrimPrefix(rest, "#"))
	}

	return CronJob{
		ID:       fmt.Sprintf("line_%d", lineNum),
		Schedule: schedule,
		Command:  command,
		Comment:  comment,
		Enabled:  enabled,
		Raw:      rawLine,
	}
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

func updateCrontabContent(existingRaw string, job CronJob) string {
	lines := strings.Split(existingRaw, "\n")
	newLine := formatCronLine(job)

	lineNum := -1
	if strings.HasPrefix(job.ID, "line_") {
		if n, err := strconv.Atoi(strings.TrimPrefix(job.ID, "line_")); err == nil {
			lineNum = n - 1
		}
	}

	if lineNum >= 0 && lineNum < len(lines) {
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
	return result
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
	cmd := exec.Command("crontab", "-l")
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
	if strings.TrimSpace(content) == "" {
		cmd := exec.Command("crontab", "-r")
		_ = cmd.Run()
		return nil
	}

	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab write failed: %v: %s", err, stderr.String())
	}
	return nil
}

func readWindowsTasks() ([]CronJob, string, error) {
	cmd := exec.Command("schtasks", "/Query", "/FO", "CSV", "/V", "/NH")
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
			Schedule: "* * * * *",
			Command:  taskToRun,
			Comment:  comment,
			Enabled:  enabled,
			Raw:      strings.Join(rec, ","),
		})
	}
	return jobs
}

func saveWindowsTask(req CronSaveRequest) error {
	taskName, err := validateWindowsTaskName(req.ID)
	if err != nil {
		return err
	}

	args := []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "DAILY", "/ST", "09:00", "/F"}
	if req.Schedule == "@hourly" {
		args = []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "HOURLY", "/F"}
	} else if req.Schedule == "@reboot" {
		args = []string{"/Create", "/TN", taskName, "/TR", req.Command, "/SC", "ONSTART", "/F"}
	}

	cmd := exec.Command("schtasks", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks /Create failed: %v: %s", err, string(out))
	}

	changeArg := "/ENABLE"
	if !req.Enabled {
		changeArg = "/DISABLE"
	}
	cmdChange := exec.Command("schtasks", "/Change", "/TN", taskName, changeArg)
	_ = cmdChange.Run()

	return nil
}

func deleteWindowsTask(id string) error {
	taskName, err := validateWindowsTaskName(id)
	if err != nil {
		return err
	}
	cmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
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

	var req CronSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
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
		if err := saveWindowsTask(req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"job": CronJob{
				ID:       req.ID,
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

	newRaw := updateCrontabContent(currentRaw, targetJob)
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
		_ = json.NewDecoder(r.Body).Decode(&req)
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
