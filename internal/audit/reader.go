package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type AuditPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Decision  string `json:"decision"`
	RiskScore int    `json:"risk_score"`
}

type AuditEntry struct {
	Timestamp       string         `json:"timestamp"`
	Command         string         `json:"command"`
	Ecosystem       string         `json:"ecosystem"`
	Packages        []AuditPackage `json:"packages"`
	Mode            string         `json:"mode"`
	InstallExecuted bool           `json:"install_executed"`
	OverrideUsed    bool           `json:"override_used"`
	Reason          string         `json:"reason,omitempty"`
}

var (
	secretParamRegex = regexp.MustCompile(`(?i)(token|password|_auth|key|secret|pass|auth)(?:=|\s+)([^/ \t\n\r]+)`)
	urlAuthRegex     = regexp.MustCompile(`(?i)(https?://)([^/ \t\n\r]+:[^/ \t\n\r]+@)`)
)

// RedactString removes secrets and auth tokens from strings.
func RedactString(s string) string {
	s = urlAuthRegex.ReplaceAllString(s, "$1[REDACTED]@")
	return secretParamRegex.ReplaceAllStringFunc(s, func(match string) string {
		if strings.Contains(match, "=") {
			parts := strings.SplitN(match, "=", 2)
			return parts[0] + "=[REDACTED]"
		}
		parts := strings.Fields(match)
		if len(parts) >= 2 {
			return parts[0] + " [REDACTED]"
		}
		return "[REDACTED]"
	})
}

// ExpandHome replaces ~/ with the user's home directory path.
func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// ReadAuditLog parses the audit log JSONL file, redacting credentials.
func ReadAuditLog(path string) ([]AuditEntry, error) {
	if path == "" {
		path = "~/.pkgsafe/audit.log"
	}
	absPath := ExpandHome(path)
	f, err := os.Open(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			entry.Command = RedactString(entry.Command)
			entry.Reason = RedactString(entry.Reason)
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}
