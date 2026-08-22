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
\\\powershell
irm https://github.com/jhkim988/every-forge-agent/releases/latest/download/every-forge-agent-win64.exe -OutFile "C:\Users\Kim_Jin_Han\every-forge-agent.exe" ; Unblock-File "C:\Users\Kim_Jin_Han\every-forge-agent.exe" ; & "C:\Users\Kim_Jin_Han\every-forge-agent.exe"
\\\

### 2. macOS (Apple Silicon / Intel)
\\\ash
curl -fsSL https://github.com/jhkim988/every-forge-agent/releases/latest/download/every-forge-agent-darwin-arm64 -o ~/every-forge-agent
chmod +x ~/every-forge-agent
~/every-forge-agent
\\\

### 3. Linux (x86_64 / ARM64)
\\\ash
curl -fsSL https://github.com/jhkim988/every-forge-agent/releases/latest/download/every-forge-agent-linux-amd64 -o ~/every-forge-agent
chmod +x ~/every-forge-agent
~/every-forge-agent
\\\

### 4. Install via Go (Developers)
\\\ash
go install github.com/jhkim988/every-forge-agent@latest
every-forge-agent
\\\

---

## 📡 Included Development Tools

### HTTP Echo Server (\:9922\)
A lightweight, fully permissive CORS HTTP echo server for testing payloads, headers, query params, and HTTP methods:
\\\ash
# Run standalone
go run ./cmd/echo-server
\\\

---

## 🔒 Security Architecture & Guarantees

1. **Localhost Binding**: Binds strictly to \127.0.0.1\. Never accepts external WAN traffic.
2. **CORS Origin Guard**: Restricted to \https://every-forge.com\, \https://www.every-forge.com\, and \http://localhost:*\.
3. **Transparent Audit**: 100% open-source under MIT License. No third-party network packages.

---

## 📄 License
MIT License © 2026 Every-Forge Team.
