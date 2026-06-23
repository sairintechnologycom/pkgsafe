package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
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
