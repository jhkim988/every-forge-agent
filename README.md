# Every-Forge Local Bridge Agent & Dev Server Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/jhkim988/every-forge-agent)](https://goreportcard.com/report/github.com/jhkim988/every-forge-agent)
[![Release](https://img.shields.io/github/v/release/jhkim988/every-forge-agent?color=purple)](https://github.com/jhkim988/every-forge-agent/releases)

Ultra-lightweight, zero-dependency local bridge daemon designed for [Every-Forge](https://every-forge.com). Enables native OS-level HTTP networking, intranet API testing, and process inspection from your browser with **zero cloud telemetry**.

---

## ⚡ Key Features

- **🛡️ 100% Zero-Telemetry & Air-Gapped**: Runs strictly on 127.0.0.1:9921 loopback socket. Zero external data collection.
- **🌐 Native CORS & Intranet Bypass**: Bypasses browser SOP (Same-Origin Policy) and Mixed Content restrictions for localhost, staging, and corporate intranet APIs.
- **⚡ Zero-Config Auto Pairing**: Automatically detects and pairs with [every-forge.com](https://every-forge.com) sessions.
- **🪟 Chrome PNA Support**: Implements Access-Control-Allow-Private-Network: true for modern browser private network access.
- **🚀 Ultra-Lightweight Binary**: Single static binary compiled with Go standard library (0 external dependencies, < 8MB RAM).

---

## 📦 Quick Installation & Usage

### 1. Windows (PowerShell 1-Click)
Run in PowerShell (bypasses SmartScreen/MOTW without popups):
```powershell
irm https://github.com/jhkim988/every-forge-agent/releases/latest/download/every-forge-agent-win64.exe -OutFile "$env:USERPROFILE\every-forge-agent.exe" ; Unblock-File "$env:USERPROFILE\every-forge-agent.exe" ; & "$env:USERPROFILE\every-forge-agent.exe"
```

### 2. macOS (Apple Silicon / Intel)
```bash
curl -fsSL https://github.com/jhkim988/every-forge-agent/releases/latest/download/every-forge-agent-darwin-arm64 -o ~/every-forge-agent
chmod +x ~/every-forge-agent
~/every-forge-agent
```

### 3. Linux (x86_64 / ARM64)
```bash
curl -fsSL https://github.com/jhkim988/every-forge-agent/releases/latest/download/every-forge-agent-linux-amd64 -o ~/every-forge-agent
chmod +x ~/every-forge-agent
~/every-forge-agent
```

### 4. Install via Go (Developers)
```bash
go install github.com/jhkim988/every-forge-agent@latest
every-forge-agent
```

---

## 📡 Included Development Tools

### HTTP Echo Server (\:9922\)
A lightweight, fully permissive CORS HTTP echo server for testing payloads, headers, query params, and HTTP methods:
```bash
# Run standalone
go run ./cmd/echo-server
```

---

## 🔒 Security Architecture & Guarantees

1. **Localhost Binding**: Binds strictly to \127.0.0.1\. Never accepts external WAN traffic.
2. **CORS Origin Guard**: Restricted to \https://every-forge.com\, \https://www.every-forge.com\, and \http://localhost:*\.
3. **Transparent Audit**: 100% open-source under MIT License. No third-party network packages.

---

## 📄 License
MIT License © 2026 Every-Forge Team.

## 🔌 Pairing Protocol

The web app at every-forge.com communicates with this agent over `http://127.0.0.1:9921`.

1. Start the agent — it loads or creates a persistent 32-char hex security token at `~/.every-forge/agent.token` (`0600`) and prints a **1-Click Pair URL** (`https://every-forge.com/download#pair=<token>`) in the console.
   - Use `-rotate-token` to regenerate and persist a fresh token.
   - Use `-ephemeral` for a one-time in-memory token without writing to disk.
2. Open the 1-Click Pair URL (which auto-pairs and immediately scrubs `#pair=` from the address bar via `history.replaceState`), or paste the token manually into the pairing UI on every-forge.com/download.
3. The site stores the token locally and sends it as `X-EF-Token` (or `Authorization: Bearer`) on every call.

### Endpoints
| Endpoint | Auth | Description |
|---|---|---|
| `GET /api/health` | optional | Liveness, version, OS/arch info, and `authenticated` boolean when `X-EF-Token` is sent |
| `POST /api/proxy` | token | Direct OS-socket HTTP(S) request (10 MB response cap, redirects NOT followed, binary-safe `bodyBase64` + `rawHeaders`) |
| `GET /api/process/list` | token | Structured process list (`processes[]`) with correlated listening ports + raw output |
| `POST /api/process/kill` | token | Terminate process by positive integer PID (`SIGTERM`/`SIGKILL`; rejects PID 1, self PID, and fractional numbers) |
| `GET /api/ports/list` | token | Live OS listening TCP sockets (`lsof` / `ss` / `netstat`) as raw output + PID-to-ports map |
| `GET /api/cron/list` | token | Read local user crontab (Unix) or `EF_*` Windows Scheduled Tasks |
| `POST /api/cron/save` | token | Add or update a local cron job / Windows Scheduled Task (with stale-line conflict guard and 5s exec timeout) |
| `POST /api/cron/delete` | token | Delete a local cron job by `line_N` ID or `EF_*` Windows task name |

Security: loopback binding only, strict origin whitelist (403 otherwise), persistent `0600` token (or `-ephemeral`), direct egress without env proxy bypass.

### Request Hardening (defense in depth)

1. **Loopback Host validation** — every request's `Host` header must target
   `localhost` / `127.0.0.1` / `[::1]` (any port). Public hostnames resolving to
   127.0.0.1 (DNS rebinding) are rejected with 403.
2. **Exact origin matching** — the CORS whitelist compares parsed hostnames, so
   look-alikes such as `http://localhost.evil.com` or
   `https://every-forge.com.evil.com` are rejected (403).
3. **Fail-closed token auth** — protected endpoints require a valid `X-EF-Token`
   or `Authorization: Bearer`; an agent without a configured token refuses them.
4. **PID validation** — `/api/process/kill?pid=` accepts positive integers within
   OS pid range only (`-1`, `0`, out-of-range → 400 before reaching the OS).

### Known Browser Limitations

- **Safari**: an HTTPS page (every-forge.com) cannot call the agent's
  `http://127.0.0.1` endpoints — Safari blocks this as mixed content with no
  per-site override. Use Chrome, Edge, or Firefox for pairing and agent-backed
  tools; the header badge will simply show *Offline* in Safari.
- Host headers carrying a trailing-dot FQDN (`localhost.`) are rejected
  fail-closed; browsers do not send that form.
