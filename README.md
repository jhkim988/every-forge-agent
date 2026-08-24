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

1. Start the agent — it prints a random 32-char security token in the console.
2. Paste that token into the agent pairing UI on every-forge.com.
3. The site stores the token locally and sends it as `X-EF-Token` (or `Authorization: Bearer`) on every call.

### Endpoints
| Endpoint | Auth | Description |
|---|---|---|
| `GET /api/health` | none | Liveness, version, OS/arch info |
| `POST /api/proxy` | token | Server-side HTTP request from your machine (response capped at 10 MB, redirects are NOT followed) |
| `GET /api/process/list` | token | Structured process list (`processes[]`) + raw output |
| `POST /api/process/kill?pid=` | token | Kill process by numeric PID (validated: positive integer only) |

Security: loopback binding only, strict origin whitelist (403 otherwise), random per-run token.
