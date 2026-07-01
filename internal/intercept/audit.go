package intercept

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
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

func LogAudit(pol policy.Policy, entry AuditEntry) error {
	// Check if audit logging is enabled by policy
	// For backward compatibility, default to true if not specified
	enabled := true
	logPath := "~/.pkgsafe/audit.log"

	// If policy has install_interception settings, check them
	// We'll read these from pol.InstallInterception.AuditLogEnabled/Path
	enabled = pol.InstallInterception.AuditLogEnabled
	if pol.InstallInterception.AuditLogPath != "" {
		logPath = pol.InstallInterception.AuditLogPath
	}

	if !enabled {
		return nil
	}

	absPath := expandHome(logPath)
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create audit log directory: %w", err)
	}

	f, err := os.OpenFile(absPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Redact tokens in command and reason
	entry.Command = RedactString(entry.Command)
	entry.Reason = RedactString(entry.Reason)

	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}

	return nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
