package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyFromYAML(t *testing.T) {
	path := writeTempPolicy(t, `
mode: block
thresholds:
  allow_max_score: 10
  warn_max_score: 20
  block_min_score: 30
protected_paths:
  - "~/.aws"
trusted_packages:
  npm:
    - axios
blocked_packages:
  npm: []
rules:
  lifecycle_script_present:
    enabled: true
    severity: low
    score: 7
`)
	pol, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Mode != ModeBlock || pol.Thresholds.BlockMinScore != 30 {
		t.Fatalf("policy did not load expected mode/thresholds: %+v", pol)
	}
	if !IsTrusted(pol, "npm", "axios") {
		t.Fatalf("expected axios to be trusted")
	}
	if rule, ok := RuleFor(pol, "lifecycle_script_present"); !ok || rule.Score != 7 || rule.Severity != "low" {
		t.Fatalf("rule did not load: %+v ok=%v", rule, ok)
	}
	// Verify dynamic BlockPatterns derivation:
	// We defined protected_paths containing only "~/.aws".
	// The derived BlockPatterns should contain "~/.aws", ".aws", and "credentials",
	// but should NOT contain "~/.ssh" or "id_rsa".
	foundAWS := false
	foundCredentials := false
	foundSSH := false
	for _, pat := range pol.BlockPatterns {
		if pat == "~/.aws" || pat == ".aws" {
			foundAWS = true
		}
		if pat == "credentials" {
			foundCredentials = true
		}
		if strings.Contains(pat, "ssh") || pat == "id_rsa" {
			foundSSH = true
		}
	}
	if !foundAWS {
		t.Errorf("expected BlockPatterns to contain ~/.aws or .aws")
	}
	if !foundCredentials {
		t.Errorf("expected BlockPatterns to contain credentials")
	}
	if foundSSH {
		t.Errorf("expected BlockPatterns to NOT contain ssh or id_rsa when ssh is not in protected_paths")
	}
}

func TestDefaultPolicyFallback(t *testing.T) {
	pol, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if pol.Mode != ModeWarn || pol.Thresholds.BlockMinScore != 70 {
		t.Fatalf("unexpected default policy: %+v", pol)
	}
}

func TestInvalidPolicyReturnsClearError(t *testing.T) {
	path := writeTempPolicy(t, `
mode: warn
thresholds:
  allow_max_score: 80
  warn_max_score: 20
  block_min_score: 30
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected invalid policy error")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "invalid policy") {
		t.Fatalf("expected clear invalid policy error, got %q", got)
	}
}

func writeTempPolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
