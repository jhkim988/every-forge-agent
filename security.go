package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (a *AgentServer) hostMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validLoopbackHost(r.Host) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "host not allowed: agent only accepts loopback Host headers",
			})
			return
		}
		next(w, r)
	}
}

// validLoopbackHost reports whether the Host header targets the local loopback.
// This is a DNS-rebinding defense: a public hostname resolving to 127.0.0.1 must
// not reach the agent, even though the connection itself arrives from loopback.
func validLoopbackHost(hostHeader string) bool {
	if hostHeader == "" {
		// Tolerate HTTP/1.0-style requests without a Host header.
		return true
	}

	// Reject userinfo (@) and URL/control characters that must never appear in a Host header.
	if strings.ContainsAny(hostHeader, "@/\\?# \t\r\n") {
		return false
	}

	h := strings.ToLower(hostHeader)

	// Direct loopback matches without port.
	if h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1" {
		return true
	}

	// Must be host:port
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		return false
	}

	if !isValidPort(port) {
		return false
	}

	if strings.HasPrefix(h, "[") {
		return host == "::1"
	}
	return host == "localhost" || host == "127.0.0.1"
}

// isValidPort reports whether port is a valid TCP port string (1-5 ASCII digits, 1..65535).
func isValidPort(port string) bool {
	if len(port) < 1 || len(port) > 5 {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	p, err := strconv.Atoi(port)
	return err == nil && p >= 1 && p <= 65535
}

func (a *AgentServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if !isAllowedOrigin(origin, a.DevMode) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "origin not allowed",
			})
			return
		}

		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-EF-Token, Authorization, Access-Control-Request-Private-Network")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		// Chrome Private Network Access (PNA) Preflight Support (https -> localhost)
		w.Header().Set("Access-Control-Allow-Private-Network", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func isAllowedOrigin(origin string, isDev bool) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())

	// Always allow production official domains (exact host match)
	if host == "every-forge.com" || host == "www.every-forge.com" {
		return true
	}
	// Allow local loopback hosts only (exact match)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	// In dev mode, allow preview deployments
	if isDev && (strings.HasSuffix(host, ".every-forge.com") || strings.HasSuffix(host, ".vercel.app")) {
		return true
	}
	return false
}

func (a *AgentServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.Token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "agent has no security token configured; refusing to serve protected endpoints",
			})
			return
		}

		token := r.Header.Get("X-EF-Token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(a.Token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Unauthorized. Missing or invalid X-EF-Token header.",
				"hint":  "Pair this browser session using the token printed in your local-agent console.",
			})
			return
		}
		next(w, r)
	}
}

// validatePid reports whether pid is a positive integer within OS pid_t range.
// This blocks dangerous values such as -1 (signal broadcast on Unix) and 0
// (process group of the caller) before they ever reach the OS.
func validatePid(pid string) bool {
	pidNum, err := strconv.Atoi(pid)
	return err == nil && pidNum > 0 && pidNum <= 4194304 // 4194304 = 2^22, default macOS pid_max
}

var (
	gcpMetadataIPv6 = net.ParseIP("fd00:ec2::254")
	alibabaIPv4     = net.IPv4(100, 100, 100, 200).To4()
	azureWireServer = net.IPv4(168, 63, 129, 16).To4()

	blockedMetadataHostnames = map[string]bool{
		"169.254.169.254":            true,
		"fd00:ec2::254":              true,
		"100.100.100.200":            true,
		"168.63.129.16":              true,
		"metadata":                   true,
		"metadata.google.internal":   true,
		"metadata.goog":              true,
		"instance-data":              true,
		"instance-data.ec2.internal": true,
	}

	blockedMetadataHosts = blockedMetadataHostnames
)

// isBlockedMetadataIP checks if the given IP belongs to cloud instance metadata services
// across AWS, GCP, Azure, Alibaba Cloud, OpenStack, and other cloud hypervisors.
func isBlockedMetadataIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Convert IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) to 4-byte IPv4
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else if ipCompat := parseIPv4Compatible(ip); ipCompat != nil {
		// Handle deprecated IPv4-compatible IPv6 (::169.254.169.254 / ::a9fe:a9fe)
		ip = ipCompat
	}

	if len(ip) == net.IPv4len {
		// RFC 3927 IPv4 Link-Local range 169.254.0.0/16 (covers 169.254.169.254, ECS 169.254.170.2, Azure 169.254.169.253)
		if ip.IsLinkLocalUnicast() {
			return true
		}
		// Alibaba Cloud metadata: 100.100.100.200
		if ip.Equal(alibabaIPv4) {
			return true
		}
		// Azure WireServer: 168.63.129.16
		if ip.Equal(azureWireServer) {
			return true
		}
		return false
	}

	// GCP / AWS IPv6 metadata: fd00:ec2::254
	if ip.Equal(gcpMetadataIPv6) {
		return true
	}
	// IPv6 Link-Local unicast (fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}

// parseIPv4Compatible checks for deprecated IPv4-compatible IPv6 addresses (0:0:0:0:0:0:a.b.c.d).
func parseIPv4Compatible(ip net.IP) net.IP {
	if len(ip) == net.IPv6len {
		for i := 0; i < 12; i++ {
			if ip[i] != 0 {
				return nil
			}
		}
		// Exclude :: and ::1
		if ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && (ip[15] == 0 || ip[15] == 1) {
			return nil
		}
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	return nil
}

// parseIPv4Alternate parses alternate IPv4 address formats supported by POSIX inet_aton:
// - Decimal integer: 2852039166
// - Dotted hex: 0xa9.0xfe.0xa9.0xfe or 0xa9fea9fe
// - Octal: 0251.0376.0251.0376 or 025177524776
// - 2-part: 169.16689662 or 169.0xfea9fe (8-bit . 24-bit)
// - 3-part: 169.254.43518 or 169.254.0xa9fe (8-bit . 8-bit . 16-bit)
// - Mixed bases across parts
func parseIPv4Alternate(s string) net.IP {
	if strings.Contains(s, ":") {
		return nil
	}
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil
	}

	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil
		}
		// Reject binary prefix 0b
		if strings.HasPrefix(p, "0b") || strings.HasPrefix(p, "0B") {
			return nil
		}
		v, err := strconv.ParseUint(p, 0, 64)
		if err != nil {
			return nil
		}
		vals[i] = v
	}

	var ipInt uint64
	switch len(parts) {
	case 1:
		if vals[0] > 0xFFFFFFFF {
			return nil
		}
		ipInt = vals[0]
	case 2:
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return nil
		}
		ipInt = (vals[0] << 24) | vals[1]
	case 3:
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return nil
		}
		ipInt = (vals[0] << 24) | (vals[1] << 16) | vals[2]
	case 4:
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFF || vals[3] > 0xFF {
			return nil
		}
		ipInt = (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]
	}

	return net.IPv4(
		byte(ipInt>>24),
		byte(ipInt>>16),
		byte(ipInt>>8),
		byte(ipInt),
	).To4()
}

// parseNormalizedIP normalizes any valid IPv4 or IPv6 representation into net.IP.
func parseNormalizedIP(host string) net.IP {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimRight(host, ".")
	if host == "" {
		return nil
	}

	// 1. Standard IPv4 / IPv6 / IPv4-mapped IPv6
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4
		}
		return ip
	}

	// 2. Alternate POSIX IPv4 notations (integer, hex, octal, mixed)
	return parseIPv4Alternate(host)
}

func isBlockedProxyTarget(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true // fail-closed on invalid URLs
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return true
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimRight(host, ".")
	lowerHost := strings.ToLower(host)

	// 1. Fast-path: check static blocklist of known metadata hostnames and IPs
	if blockedMetadataHostnames[lowerHost] {
		return true
	}

	// 2. IP Literal Check (decimal, hex, octal, IPv4, IPv6, IPv6-mapped IPv4)
	if ip := parseNormalizedIP(host); ip != nil {
		return isBlockedMetadataIP(ip)
	}

	// 3. Hostname Resolution Check: resolve domain and inspect all returned IPs
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err == nil {
		for _, resolvedIP := range ips {
			if isBlockedMetadataIP(resolvedIP) {
				return true
			}
		}
	}

	return false
}

var (
	validMacroRegex = regexp.MustCompile(`(?i)^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$`)
	validTaskName   = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
)

func isValidCronSchedule(schedule string) bool {
	schedule = strings.TrimSpace(schedule)
	if schedule == "" {
		return false
	}
	if validMacroRegex.MatchString(schedule) {
		return true
	}

	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return false
	}

	// minute: 0-59
	if !validateCronField(fields[0], 0, 59, nil) {
		return false
	}
	// hour: 0-23
	if !validateCronField(fields[1], 0, 23, nil) {
		return false
	}
	// day of month: 1-31
	if !validateCronField(fields[2], 1, 31, nil) {
		return false
	}
	// month: 1-12 or JAN-DEC
	months := []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}
	if !validateCronField(fields[3], 1, 12, months) {
		return false
	}
	// day of week: 0-7 or SUN-SAT
	days := []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
	if !validateCronField(fields[4], 0, 7, days) {
		return false
	}

	return true
}

func validateCronField(field string, minVal, maxVal int, names []string) bool {
	if field == "*" {
		return true
	}
	parts := strings.Split(field, ",")
	for _, part := range parts {
		if part == "" {
			return false
		}
		if strings.Contains(part, "/") {
			subParts := strings.Split(part, "/")
			if len(subParts) != 2 {
				return false
			}
			step, err := strconv.Atoi(subParts[1])
			if err != nil || step <= 0 {
				return false
			}
			if subParts[0] == "*" {
				continue
			}
			part = subParts[0]
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return false
			}
			v1, ok1 := parseValOrName(rangeParts[0], minVal, maxVal, names)
			v2, ok2 := parseValOrName(rangeParts[1], minVal, maxVal, names)
			if !ok1 || !ok2 || v1 > v2 {
				return false
			}
			continue
		}
		if _, ok := parseValOrName(part, minVal, maxVal, names); !ok {
			return false
		}
	}
	return true
}

func parseValOrName(valStr string, minVal, maxVal int, names []string) (int, bool) {
	valStr = strings.ToUpper(strings.TrimSpace(valStr))
	if names != nil {
		for idx, name := range names {
			if valStr == name {
				return minVal + idx, true
			}
		}
	}
	v, err := strconv.Atoi(valStr)
	if err != nil {
		return 0, false
	}
	if v < minVal || v > maxVal {
		return 0, false
	}
	return v, true
}

func validateCronJobInput(req CronSaveRequest) error {
	if strings.TrimSpace(req.Command) == "" {
		return errors.New("command cannot be empty")
	}
	if strings.ContainsAny(req.Command, "\r\n\x00") {
		return errors.New("command cannot contain newline or null characters")
	}
	if strings.ContainsAny(req.Schedule, "\r\n\x00") {
		return errors.New("schedule cannot contain newline or null characters")
	}
	if strings.ContainsAny(req.Comment, "\r\n\x00") {
		return errors.New("comment cannot contain newline or null characters")
	}
	if !isValidCronSchedule(req.Schedule) {
		return errors.New("invalid cron schedule expression")
	}
	return nil
}

func validateWindowsTaskName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "EF_") {
		name = "EF_" + name
	}
	if !validTaskName.MatchString(name) {
		return "", errors.New("invalid task name: must be alphanumeric, hyphen or underscore (1-64 chars)")
	}
	return name, nil
}
