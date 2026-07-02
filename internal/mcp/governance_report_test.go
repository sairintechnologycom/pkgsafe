package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPGenerateGovernanceReport(t *testing.T) {
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// Write mock package-lock.json
	lockContent := `{"name":"mock-repo","packages":{"node_modules/axios":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(tempHome, "package-lock.json"), []byte(lockContent), 0644); err != nil {
		t.Fatal(err)
	}

	exec := &Executor{
		PolicyPath: "",
		Mode:       "warn",
		Offline:    true,
	}

	argsJSON := `{
		"repo_path": "` + strings.ReplaceAll(tempHome, `\`, `\\`) + `",
		"format": "json",
		"include_audit_log": false
	}`

	res := exec.GenerateGovernanceReport(json.RawMessage(argsJSON))
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content[0].Text)
	}

	var toolRes GenerateGovernanceReportResult
	if err := json.Unmarshal([]byte(res.Content[0].Text), &toolRes); err != nil {
		t.Fatal(err)
	}

	if !toolRes.ReportGenerated {
		t.Errorf("expected report_generated to be true")
	}
	if len(toolRes.Files) == 0 {
		t.Errorf("expected report files list to be populated")
	}
}

func TestMCPGetRecentPackageDecisions(t *testing.T) {
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// Write a mock audit log
	auditLogPath := filepath.Join(tempHome, ".pkgsafe", "audit.log")
	if err := os.MkdirAll(filepath.Dir(auditLogPath), 0755); err != nil {
		t.Fatal(err)
	}
	logContent := `{"timestamp":"2026-06-23T10:30:00Z","command":"npm install axios","ecosystem":"npm","packages":[{"name":"axios","version":"1.0.0","decision":"allow","risk_score":10}],"mode":"warn","install_executed":true,"override_used":false}
`
	if err := os.WriteFile(auditLogPath, []byte(logContent), 0644); err != nil {
		t.Fatal(err)
	}

	exec := &Executor{
		PolicyPath: "",
		Mode:       "warn",
		Offline:    true,
	}

	argsJSON := `{"limit": 5}`
	res := exec.GetRecentPackageDecisions(json.RawMessage(argsJSON))
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content[0].Text)
	}

	var decisions []DecisionItem
	if err := json.Unmarshal([]byte(res.Content[0].Text), &decisions); err != nil {
		t.Fatal(err)
	}

	if len(decisions) != 1 {
		t.Errorf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0].Package != "axios" {
		t.Errorf("expected axios package, got %q", decisions[0].Package)
	}
}

func TestMCPGetPolicyEvidence(t *testing.T) {
	exec := &Executor{
		PolicyPath: "",
		Mode:       "warn",
		Offline:    true,
	}

	argsJSON := `{}`
	res := exec.GetPolicyEvidence(json.RawMessage(argsJSON))
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content[0].Text)
	}

	var evidence map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &evidence); err != nil {
		t.Fatal(err)
	}

	if evidence["policy_name"] != "default-policy" {
		t.Errorf("expected default policy name, got %v", evidence["policy_name"])
	}
}
