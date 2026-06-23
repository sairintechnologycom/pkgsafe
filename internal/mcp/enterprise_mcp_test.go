package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestMCPValidatePackageInstallWithEnterpriseFields(t *testing.T) {
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// Populate cache
	store, err := cache.Load("")
	if err != nil {
		t.Fatal(err)
	}
	fakeRes := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "npm",
			Name:      "@company/design-system",
			Version:   "1.0.0",
		},
		Decision: types.DecisionAllow,
		Score:    5,
	}
	if err := store.Put(fakeRes); err != nil {
		t.Fatal(err)
	}

	// Set up a mock policy pack directory
	packDir := filepath.Join(tempHome, ".pkgsafe", "policy-packs", "enterprise-standard", "2026.06.01")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatal(err)
	}

	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01",
		"owner": "Platform Engineering",
		"compatibility": {
			"min_pkgsafe_version": "0.1.0"
		}
	}`
	policyYAML := `
mode: warn
registries:
  npm:
    company:
      url: "https://npm.company.com/"
      type: private
      enabled: true
      scopes:
        - "@company"
`
	if err := os.WriteFile(filepath.Join(packDir, "metadata.json"), []byte(metaJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "policy.yaml"), []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	exec := &Executor{
		PolicyPath: "",
		Mode:       "warn",
		Offline:    true, // Offline to avoid hitting actual internet
	}

	argsJSON := `{
		"ecosystem": "npm",
		"name": "@company/design-system",
		"version": "1.0.0",
		"requested_by": "ai_agent",
		"policy_pack": "enterprise-standard",
		"registry": "company",
		"offline": true
	}`

	res := exec.ValidatePackageInstall(json.RawMessage(argsJSON))
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content[0].Text)
	}

	var toolRes ValidatePackageInstallResult
	if err := json.Unmarshal([]byte(res.Content[0].Text), &toolRes); err != nil {
		t.Fatal(err)
	}

	// Verify policy evidence
	if toolRes.Policy == nil || toolRes.Policy.Name != "enterprise-standard" || toolRes.Policy.Version != "2026.06.01" {
		t.Errorf("expected enterprise policy pack evidence, got %+v", toolRes.Policy)
	}

	// Verify registry evidence
	if toolRes.Registry == nil || toolRes.Registry.Name != "company" || toolRes.Registry.Type != "private" {
		t.Errorf("expected company registry evidence, got %+v", toolRes.Registry)
	}
}

func TestMCPValidatePackageInstallUnknownRegistryAI(t *testing.T) {
	// AI agent installing from unknown registry
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// Populate cache
	store, err := cache.Load("")
	if err != nil {
		t.Fatal(err)
	}
	fakeRes := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "npm",
			Name:      "axios",
			Version:   "1.0.0",
		},
		Decision: types.DecisionAllow,
		Score:    5,
	}
	if err := store.Put(fakeRes); err != nil {
		t.Fatal(err)
	}

	packDir := filepath.Join(tempHome, ".pkgsafe", "policy-packs", "enterprise-standard", "2026.06.01")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatal(err)
	}

	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01"
	}`
	policyYAML := `
mode: warn
scoped_rules:
  - id: "ai_strict"
    match:
      requested_by: "ai_agent"
    apply:
      block_on_unknown_registry: true
`
	if err := os.WriteFile(filepath.Join(packDir, "metadata.json"), []byte(metaJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "policy.yaml"), []byte(policyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	exec := &Executor{
		PolicyPath: "",
		Mode:       "warn",
		Offline:    true,
	}

	// Scan package using unknown registry name "unknown-reg"
	argsJSON := `{
		"ecosystem": "npm",
		"name": "axios",
		"version": "1.0.0",
		"requested_by": "ai_agent",
		"policy_pack": "enterprise-standard",
		"registry": "unknown-reg",
		"offline": true
	}`

	res := exec.ValidatePackageInstall(json.RawMessage(argsJSON))
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content[0].Text)
	}

	var toolRes ValidatePackageInstallResult
	if err := json.Unmarshal([]byte(res.Content[0].Text), &toolRes); err != nil {
		t.Fatal(err)
	}

	// Should be blocked because block_on_unknown_registry matches ai_agent
	if toolRes.InstallAllowed {
		t.Errorf("expected AI agent to be blocked on unknown registry, but install was allowed")
	}
	if toolRes.Decision != string(policy.ModeBlock) {
		t.Errorf("expected block decision, got %s", toolRes.Decision)
	}
}

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

	if evidence["policy_pack_name"] != "enterprise-standard" {
		t.Errorf("expected default policy pack name, got %v", evidence["policy_pack_name"])
	}
}

