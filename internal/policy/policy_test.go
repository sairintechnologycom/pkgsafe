package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPolicyFromYAML(t *testing.T) {
	path := writeTempPolicy(t, `
mode: block
thresholds:
  allow_max_score: 10
  warn_max_score: 20
  block_min_score: 30
ci:
  fail_on: warn
  changed_only: false
  comment_pr: true
  upload_sarif: false
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
    block_in_strict_mode: true
`)
	pol, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if pol.CI.FailOn != "warn" || pol.CI.ChangedOnly != false || pol.CI.CommentPR != true || pol.CI.UploadSARIF != false {
		t.Fatalf("policy did not load expected ci settings: %+v", pol.CI)
	}
	if pol.Mode != ModeBlock || pol.Thresholds.BlockMinScore != 30 {
		t.Fatalf("policy did not load expected mode/thresholds: %+v", pol)
	}
	if !IsTrusted(pol, "npm", "axios") {
		t.Fatalf("expected axios to be trusted")
	}
	if rule, ok := RuleFor(pol, "lifecycle_script_present"); !ok || rule.Score != 7 || rule.Severity != "low" || !rule.BlockInStrictMode {
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

func TestPolicyRejectsUnsupportedSchemaVersion(t *testing.T) {
	path := writeTempPolicy(t, `
schema_version: "9.9"
mode: warn
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected unsupported schema version error")
	}
	if !strings.Contains(err.Error(), "unsupported schema_version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyRejectsWeakenedHardBlockRule(t *testing.T) {
	path := writeTempPolicy(t, `
schema_version: "1.0"
mode: warn
rules:
  known_malware_indicator:
    enabled: true
    severity: high
    score: 20
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected weakened hard-block rule error")
	}
	if !strings.Contains(err.Error(), "known_malware_indicator must remain critical") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyRejectsWeakenedSecurityEnforcementClass(t *testing.T) {
	path := writeTempPolicy(t, `
schema_version: "1.0"
mode: warn
rules:
  dependency_confusion_candidate:
    enabled: true
    severity: critical
    score: 100
    enforcement_class: advisory
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "enforcement_class cannot be weakened") {
		t.Fatalf("expected security enforcement weakening rejection, got %v", err)
	}
}

func TestPolicyRejectsForceAcceptWithoutReason(t *testing.T) {
	path := writeTempPolicy(t, `
schema_version: "1.0"
mode: warn
install_interception:
  enabled: true
  default_mode: warn
  allow_force_risk_accept: true
  force_risk_accept_requires_reason: false
  block_known_malware_always: true
  block_credential_access_always: true
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected force risk accept reason error")
	}
	if !strings.Contains(err.Error(), "force risk accept must require a reason") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyRejectsExceptionWithoutAuditFields(t *testing.T) {
	pol := Default()
	pol.Exceptions = []Exception{{
		ID:           "EXC-1",
		Ecosystem:    "npm",
		Package:      "legacy",
		AllowedUntil: time.Now().Add(24 * time.Hour),
	}}
	err := Validate(pol)
	if err == nil {
		t.Fatal("expected missing exception reason error")
	}
	if !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("unexpected error: %v", err)
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

func TestLoadAgentPolicy(t *testing.T) {
	path := writeTempPolicy(t, `
schema_version: "1.0"
mode: warn
agent_policy:
  mode: block
  warn_requires_human: true
  block_install_commands: true
  allow_agent_exceptions: false
  require_pkg_safe_check_before_install: true
`)
	pol, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ap := pol.AgentPolicy
	if ap.Mode != "block" {
		t.Errorf("expected Mode 'block', got %q", ap.Mode)
	}
	if !ap.WarnRequiresHuman {
		t.Errorf("expected WarnRequiresHuman to be true")
	}
	if !ap.BlockInstallCommands {
		t.Errorf("expected BlockInstallCommands to be true")
	}
	if ap.AllowAgentExceptions {
		t.Errorf("expected AllowAgentExceptions to be false")
	}
	if !ap.RequirePkgSafeCheckBeforeInstall {
		t.Errorf("expected RequirePkgSafeCheckBeforeInstall to be true")
	}
}
