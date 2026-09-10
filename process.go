package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ProcessItem struct {
	PID     string   `json:"pid"`
	Name    string   `json:"name"`
	Memory  string   `json:"memory,omitempty"`
	Session string   `json:"session,omitempty"`
	User    string   `json:"user,omitempty"`
	CPU     string   `json:"cpu,omitempty"`
	Ports   []string `json:"ports,omitempty"`
}

type ProcessKillRequest struct {
	PID    interface{} `json:"pid"`
	Signal string      `json:"signal,omitempty"`
}

type ProcessKillResponse struct {
	Status string `json:"status"`
	PID    string `json:"pid,omitempty"`
	Signal string `json:"signal,omitempty"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

var (
	ssPidRegex        = regexp.MustCompile(`pid=(\d+)`)
	linuxNetstatRegex = regexp.MustCompile(`^(\d+)/`)
)

// parseProcessList converts raw OS process listings into structured items.
// Supports macOS/Linux `ps` output and Windows `tasklist /FO CSV /NH`.
func parseProcessList(raw string, goos string) []ProcessItem {
	items := []ProcessItem{}
	if goos == "windows" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "\"") {
				continue
			}
			fields := strings.Split(line, "\",\"")
			if len(fields) < 5 {
				continue
			}
			items = append(items, ProcessItem{
				Name:    strings.Trim(fields[0], "\""),
				PID:     strings.Trim(fields[1], "\""),
				Session: strings.Trim(fields[2], "\""),
				Memory:  strings.Trim(fields[4], "\""),
			})
		}
		return items
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		items = append(items, ProcessItem{
			PID:    fields[0],
			User:   fields[1],
			CPU:    fields[2],
			Memory: fields[3],
			Name:   strings.Join(fields[4:], " "),
		})
	}
	return items
}

// getListeningPortsByPID executes OS socket inspection commands with a timeout
// and returns a map from PID to unique, sorted port tags (e.g. ["tcp/3000", "tcp/8080"]).
func getListeningPortsByPID(goos string) map[string][]string {
	portMap := make(map[string][]string)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	switch goos {
	case "windows":
		cmd := exec.CommandContext(ctx, "netstat", "-ano", "-p", "tcp")
		if out, err := cmd.Output(); err == nil {
			parseWindowsNetstatOutput(string(out), portMap)
		}
	case "darwin":
		cmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
		if out, err := cmd.Output(); err == nil {
			parseLsofOutput(string(out), portMap)
		}
	case "linux":
		// 1. Primary: ss -tlnp
		cmd := exec.CommandContext(ctx, "ss", "-tlnp")
		if out, err := cmd.Output(); err == nil && len(out) > 0 {
			parseSsOutput(string(out), portMap)
		}
		// 2. Fallback to lsof if ss returned nothing
		if len(portMap) == 0 {
			cmdLsof := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
			if outLsof, errLsof := cmdLsof.Output(); errLsof == nil && len(outLsof) > 0 {
				parseLsofOutput(string(outLsof), portMap)
			}
		}
		// 3. Fallback to netstat if still empty
		if len(portMap) == 0 {
			cmdNetstat := exec.CommandContext(ctx, "netstat", "-tlnp")
			if outNetstat, errNetstat := cmdNetstat.Output(); errNetstat == nil {
				parseLinuxNetstatOutput(string(outNetstat), portMap)
			}
		}
	}

	sortPortMap(portMap)
	return portMap
}

// parseLsofOutput parses macOS / Unix `lsof -nP -iTCP -sTCP:LISTEN` stdout.
func parseLsofOutput(raw string, portMap map[string][]string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid := fields[1]
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// fields[7] is PROTO (TCP), fields[8] is NAME/address, fields[9] is (LISTEN)
		addrField := fields[8]
		proto := "tcp"
		if len(fields) > 7 && strings.HasPrefix(strings.ToLower(fields[7]), "tcp") {
			proto = "tcp"
		}

		lastColon := strings.LastIndex(addrField, ":")
		if lastColon == -1 {
			continue
		}
		portStr := addrField[lastColon+1:]
		if portNum, err := strconv.Atoi(portStr); err == nil && portNum > 0 && portNum <= 65535 {
			tag := fmt.Sprintf("%s/%d", proto, portNum)
			addUniquePort(portMap, pid, tag)
		}
	}
}

// parseSsOutput parses Linux `ss -tlnp` stdout.
func parseSsOutput(raw string, portMap map[string][]string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}
		if !strings.Contains(line, "LISTEN") {
			continue
		}

		// Extract PIDs from `users:(("...",pid=1234,...))`
		matches := ssPidRegex.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Field with local address is typically index 3 (if Netid omitted) or index 4
		localAddr := fields[3]
		if fields[0] != "LISTEN" && len(fields) >= 5 {
			localAddr = fields[4]
		}

		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon == -1 {
			continue
		}
		portStr := localAddr[lastColon+1:]
		if portNum, err := strconv.Atoi(portStr); err == nil && portNum > 0 && portNum <= 65535 {
			tag := fmt.Sprintf("tcp/%d", portNum)
			for _, m := range matches {
				addUniquePort(portMap, m[1], tag)
			}
		}
	}
}

// parseLinuxNetstatOutput parses Linux `netstat -tlnp` stdout.
func parseLinuxNetstatOutput(raw string, portMap map[string][]string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
			continue
		}
		if fields[5] != "LISTEN" {
			continue
		}

		localAddr := fields[3]
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon == -1 {
			continue
		}
		portStr := localAddr[lastColon+1:]
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum <= 0 || portNum > 65535 {
			continue
		}

		pidProg := fields[6]
		match := linuxNetstatRegex.FindStringSubmatch(pidProg)
		if len(match) < 2 {
			continue
		}
		pid := match[1]
		tag := fmt.Sprintf("tcp/%d", portNum)
		addUniquePort(portMap, pid, tag)
	}
}

// parseWindowsNetstatOutput parses Windows `netstat -ano -p tcp` stdout.
func parseWindowsNetstatOutput(raw string, portMap map[string][]string) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		if !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}

		pid := fields[4]
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		localAddr := fields[1]
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon == -1 {
			continue
		}
		portStr := localAddr[lastColon+1:]
		if portNum, err := strconv.Atoi(portStr); err == nil && portNum > 0 && portNum <= 65535 {
			tag := fmt.Sprintf("tcp/%d", portNum)
			addUniquePort(portMap, pid, tag)
		}
	}
}

// addUniquePort appends portTag to portMap[pid] only if not already present.
func addUniquePort(portMap map[string][]string, pid, portTag string) {
	for _, p := range portMap[pid] {
		if p == portTag {
			return
		}
	}
	portMap[pid] = append(portMap[pid], portTag)
}

// sortPortMap sorts all ports numerically in ascending order (e.g. tcp/80 before tcp/3000).
func sortPortMap(portMap map[string][]string) {
	for pid, ports := range portMap {
		sort.Slice(ports, func(i, j int) bool {
			numI := extractPortNumber(ports[i])
			numJ := extractPortNumber(ports[j])
			if numI != numJ {
				return numI < numJ
			}
			return ports[i] < ports[j]
		})
		portMap[pid] = ports
	}
}

func extractPortNumber(tag string) int {
	if i := strings.LastIndex(tag, "/"); i != -1 {
		if n, err := strconv.Atoi(tag[i+1:]); err == nil {
			return n
		}
	}
	return 0
}

// correlateProcessPorts correlates process items with listening ports by PID.
func correlateProcessPorts(items []ProcessItem, portMap map[string][]string) []ProcessItem {
	if len(portMap) == 0 {
		return items
	}
	for i := range items {
		if ports, ok := portMap[items[i].PID]; ok && len(ports) > 0 {
			items[i].Ports = ports
		}
	}
	return items
}

// handleProcessList responds with processes and correlated listening ports.
func (a *AgentServer) handleProcessList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	} else {
		cmd = exec.CommandContext(ctx, "ps", "-eo", "pid,user,%cpu,%mem,comm")
	}

	out, err := cmd.Output()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to inspect processes: " + err.Error()})
		return
	}

	processes := parseProcessList(string(out), runtime.GOOS)
	portMap := getListeningPortsByPID(runtime.GOOS)
	processes = correlateProcessPorts(processes, portMap)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"os":        runtime.GOOS,
		"raw":       string(out),
		"processes": processes,
		"status":    "success",
	})
}

// handleProcessKill terminates a process safely with strict validation and signal support.
func (a *AgentServer) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  "Method Not Allowed: use POST",
		})
		return
	}

	var reqData ProcessKillRequest
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &reqData)
		}
	}

	var pidStr string
	switch v := reqData.PID.(type) {
	case string:
		pidStr = strings.TrimSpace(v)
	case float64:
		pidStr = strconv.Itoa(int(v))
	case int:
		pidStr = strconv.Itoa(v)
	}
	if pidStr == "" {
		pidStr = strings.TrimSpace(r.URL.Query().Get("pid"))
	}

	signalStr := strings.TrimSpace(reqData.Signal)
	if signalStr == "" {
		signalStr = strings.TrimSpace(r.URL.Query().Get("signal"))
	}

	if pidStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  "missing pid parameter",
		})
		return
	}

	if !validatePid(pidStr) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  "invalid pid: must be a positive integer within OS pid range",
			PID:    pidStr,
		})
		return
	}

	pidNum, _ := strconv.Atoi(pidStr)
	if pidNum == 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  "refusing to terminate system init (PID 1)",
			PID:    pidStr,
		})
		return
	}

	if pidNum == os.Getpid() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  "refusing to terminate agent process itself",
			PID:    pidStr,
		})
		return
	}

	sigNorm := strings.ToUpper(signalStr)
	if sigNorm == "" || sigNorm == "SIGTERM" || sigNorm == "15" {
		sigNorm = "SIGTERM"
	} else if sigNorm == "SIGKILL" || sigNorm == "9" {
		sigNorm = "SIGKILL"
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  "unsupported signal: must be SIGTERM (15) or SIGKILL (9)",
			PID:    pidStr,
		})
		return
	}

	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if runtime.GOOS == "windows" {
		if sigNorm == "SIGKILL" {
			cmd = exec.CommandContext(ctx, "taskkill", "/F", "/PID", pidStr)
		} else {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", pidStr)
		}
	} else {
		sigArg := "-15"
		if sigNorm == "SIGKILL" {
			sigArg = "-9"
		}
		cmd = exec.CommandContext(ctx, "kill", sigArg, pidStr)
	}

	out, err := cmd.CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ProcessKillResponse{
			Status: "error",
			Error:  err.Error(),
			Output: string(out),
			PID:    pidStr,
			Signal: sigNorm,
		})
		return
	}

	json.NewEncoder(w).Encode(ProcessKillResponse{
		Status: "killed",
		PID:    pidStr,
		Signal: sigNorm,
		Output: string(out),
	})
}
