package feedback

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateGeneratesRedactedFeedbackArtifacts(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "scan.json")
	raw := `{
  "ecosystem": "npm",
  "package": "example-package",
  "version": "1.2.3",
  "decision": "warn",
  "risk_score": 62,
  "reasons": [
    {"rule_id": "lifecycle_script_present", "severity": "medium", "message": "Package defines a postinstall script", "score": 20},
    {"rule_id": "network_command_in_lifecycle", "severity": "high", "message": "Uses Bearer npm_abcdefghijklmnopqrstuvwxyz123456", "score": 30}
  ],
  "lifecycle_scripts": ["postinstall"],
  "registry": {"name": "internal", "type": "private", "url": "https://user:pass@example.test/npm/"}
}`
	if err := os.WriteFile(input, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	artifacts, err := Create(Options{
		InputPath: input,
		OutputDir: filepath.Join(tmp, "feedback"),
		Reason:    "Reviewed source. Token npm_abcdefghijklmnopqrstuvwxyz123456 must not leak.",
		Command:   "pkgsafe scan-npm-package example-package --json --token npm_abcdefghijklmnopqrstuvwxyz123456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.Feedback.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
	if !artifacts.Feedback.PrivateRegistryInvolved {
		t.Fatal("expected private registry involvement")
	}
	if !artifacts.Feedback.LifecycleScriptsInvolved {
		t.Fatal("expected lifecycle scripts involvement")
	}
	jsonBytes, err := os.ReadFile(artifacts.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	mdBytes, err := os.ReadFile(artifacts.MarkdownPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{string(jsonBytes), string(mdBytes)} {
		if strings.Contains(content, "npm_abcdefghijklmnopqrstuvwxyz123456") || strings.Contains(content, "user:pass") {
			t.Fatalf("feedback artifact leaked secret:\n%s", content)
		}
		if !strings.Contains(content, "[REDACTED]") && !strings.Contains(content, "REDACTED") {
			t.Fatalf("expected redaction marker in artifact:\n%s", content)
		}
	}
	var decoded FindingFeedback
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Package != "example-package" || decoded.Ecosystem != "npm" || decoded.Version != "1.2.3" {
		t.Fatalf("unexpected decoded feedback: %+v", decoded)
	}
}

func TestFingerprintStableAcrossRuleOrder(t *testing.T) {
	base := FindingFeedback{
		Ecosystem: "npm",
		Package:   "example",
		Version:   "1.0.0",
		Decision:  "warn",
		RiskScore: 50,
		RuleIDs:   []string{"b_rule", "a_rule"},
	}
	reordered := base
	reordered.RuleIDs = []string{"a_rule", "b_rule"}
	if Fingerprint(base) != Fingerprint(reordered) {
		t.Fatal("expected fingerprint to be stable across rule order")
	}
}

func TestCreateRejectsMalformedInput(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "scan.json")
	if err := os.WriteFile(input, []byte(`{"package":"example"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Create(Options{InputPath: input, OutputDir: filepath.Join(tmp, "feedback")})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "package, ecosystem, and decision") {
		t.Fatalf("unexpected error: %v", err)
	}
}
