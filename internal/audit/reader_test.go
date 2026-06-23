package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAuditLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "audit-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.log")
	logContent := `{"timestamp":"2026-06-23T10:30:00Z","command":"npm install axios --token=secret123","ecosystem":"npm","packages":[{"name":"axios","version":"1.0.0","decision":"allow","risk_score":10}],"mode":"warn","install_executed":true,"override_used":false}
{"timestamp":"2026-06-23T10:35:00Z","command":"pip install requests","ecosystem":"pypi","packages":[{"name":"requests","version":"2.28.1","decision":"block","risk_score":85}],"mode":"block","install_executed":false,"override_used":true,"reason":"Developer forced bypass with --force-risk-accept password=pass123"}
`
	if err := os.WriteFile(logPath, []byte(logContent), 0600); err != nil {
		t.Fatalf("failed to write audit log: %v", err)
	}

	entries, err := ReadAuditLog(logPath)
	if err != nil {
		t.Fatalf("ReadAuditLog failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Verify token redaction
	if entries[0].Command != "npm install axios --token=[REDACTED]" {
		t.Errorf("expected redacted token in command, got %q", entries[0].Command)
	}
	if !entries[1].OverrideUsed {
		t.Errorf("expected override_used to be true for second entry")
	}
	expectedReason := "Developer forced bypass [REDACTED] --force-risk-accept password=[REDACTED]"
	if entries[1].Reason != expectedReason {
		t.Errorf("expected redacted password in reason, got %q", entries[1].Reason)
	}
}
