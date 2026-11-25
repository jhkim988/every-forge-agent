package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const persistentTokenFilename = "agent.token"

// resolveAgentToken resolves the security token for CLI execution:
//   - explicitToken != "": uses it directly without writing to disk.
//   - ephemeral == true: returns "" so NewAgentServer generates a one-time in-memory token.
//   - otherwise: loads or creates ~/.every-forge/agent.token (0600), regenerating if rotate == true.
func resolveAgentToken(explicitToken, configDir string, ephemeral, rotate bool) (string, string, error) {
	if trimmed := strings.TrimSpace(explicitToken); trimmed != "" {
		return trimmed, "", nil
	}
	if ephemeral {
		return "", "", nil
	}

	dir := strings.TrimSpace(configDir)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("resolve home dir: %w", err)
		}
		dir = filepath.Join(home, ".every-forge")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("create agent config dir: %w", err)
	}

	tokenPath := filepath.Join(dir, persistentTokenFilename)
	if !rotate {
		if raw, err := os.ReadFile(tokenPath); err == nil {
			existing := strings.TrimSpace(string(raw))
			if len(existing) >= 16 && len(existing) <= 128 && !strings.ContainsAny(existing, " \t\r\n") {
				return existing, tokenPath, nil
			}
		}
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate random token: %w", err)
	}
	tok := hex.EncodeToString(b)
	if err := os.WriteFile(tokenPath, []byte(tok+"\n"), 0600); err != nil {
		return "", "", fmt.Errorf("write persistent token: %w", err)
	}
	_ = os.Chmod(tokenPath, 0600)
	return tok, tokenPath, nil
}
