package intercept

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestExtractSafetyFlags(t *testing.T) {
	args := []string{"install", "axios", "--yes", "--mode", "block", "--policy", "custom.yaml", "--offline", "--sandbox", "--dry-run", "--force-risk-accept", "--reason", "testing"}
	clean, sf := ExtractSafetyFlags(args)

	if len(clean) != 2 || clean[0] != "install" || clean[1] != "axios" {
		t.Errorf("expected clean args to be ['install', 'axios'], got %v", clean)
	}
	if !sf.Yes {
		t.Error("expected Yes to be true")
	}
	if sf.Mode != "block" {
		t.Errorf("expected Mode to be 'block', got %q", sf.Mode)
	}
	if sf.PolicyPath != "custom.yaml" {
		t.Errorf("expected PolicyPath to be 'custom.yaml', got %q", sf.PolicyPath)
	}
	if !sf.Offline {
		t.Error("expected Offline to be true")
	}
	if !sf.Sandbox {
		t.Error("expected Sandbox to be true")
	}
	if !sf.DryRun {
		t.Error("expected DryRun to be true")
	}
	if !sf.ForceRiskAccept {
		t.Error("expected ForceRiskAccept to be true")
	}
	if sf.Reason != "testing" {
		t.Errorf("expected Reason to be 'testing', got %q", sf.Reason)
	}
}

func TestParseNPMCommands(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr bool
		verify      func(*testing.T, *InstallCommand)
	}{
		{
			name: "npm install axios",
			args: []string{"install", "axios"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if cmd.Operation != "install" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "axios" {
					t.Errorf("failed npm install axios verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm i axios",
			args: []string{"i", "axios"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if cmd.Operation != "i" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "axios" {
					t.Errorf("failed npm i axios verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm add axios",
			args: []string{"add", "axios"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if cmd.Operation != "add" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "axios" {
					t.Errorf("failed npm add axios verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm install axios@1.7.9",
			args: []string{"install", "axios@1.7.9"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if cmd.Packages[0].Name != "axios" || cmd.Packages[0].VersionSpecifier != "1.7.9" {
					t.Errorf("failed npm install axios@1.7.9 verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm install axios lodash",
			args: []string{"install", "axios", "lodash"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if len(cmd.Packages) != 2 || cmd.Packages[0].Name != "axios" || cmd.Packages[1].Name != "lodash" {
					t.Errorf("failed npm install multiple packages verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm install --save-dev eslint",
			args: []string{"install", "--save-dev", "eslint"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if len(cmd.Packages) != 1 || cmd.Packages[0].Name != "eslint" || !cmd.Packages[0].IsDevDependency {
					t.Errorf("failed devDep verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm install -D typescript",
			args: []string{"install", "-D", "typescript"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if len(cmd.Packages) != 1 || cmd.Packages[0].Name != "typescript" || !cmd.Packages[0].IsDevDependency {
					t.Errorf("failed devDep short verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm install (project install)",
			args: []string{"install"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if !cmd.IsProjectInstall || len(cmd.DependencyFiles) != 1 || cmd.DependencyFiles[0] != "package.json" {
					t.Errorf("failed project install verification: %+v", cmd)
				}
			},
		},
		{
			name: "npm ci",
			args: []string{"ci"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if !cmd.IsCIInstall || len(cmd.DependencyFiles) != 1 || cmd.DependencyFiles[0] != "package-lock.json" {
					t.Errorf("failed npm ci verification: %+v", cmd)
				}
			},
		},
		{
			name:        "unsupported npm command",
			args:        []string{"run", "build"},
			expectedErr: true,
		},
		{
			name:        "unsupported advanced npm inputs",
			args:        []string{"install", "git+https://github.com/user/repo.git"},
			expectedErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := ParseNPM(tc.args)
			if tc.expectedErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.verify(t, cmd)
		})
	}
}

func TestParsePipCommands(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr bool
		verify      func(*testing.T, *InstallCommand)
	}{
		{
			name: "pip install requests",
			args: []string{"install", "requests"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if cmd.Operation != "install" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "requests" || cmd.Packages[0].VersionSpecifier != "" {
					t.Errorf("failed pip install requests: %+v", cmd)
				}
			},
		},
		{
			name: "pip install requests==2.31.0",
			args: []string{"install", "requests==2.31.0"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if len(cmd.Packages) != 1 || cmd.Packages[0].Name != "requests" || cmd.Packages[0].ExactVersion != "2.31.0" {
					t.Errorf("failed pip exact version: %+v", cmd)
				}
			},
		},
		{
			name: "pip install requests>=2.31.0",
			args: []string{"install", "requests>=2.31.0"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if len(cmd.Packages) != 1 || cmd.Packages[0].Name != "requests" || cmd.Packages[0].VersionSpecifier != ">=2.31.0" || cmd.Packages[0].ExactVersion != "" {
					t.Errorf("failed pip range version: %+v", cmd)
				}
			},
		},
		{
			name: "pip install -r requirements.txt",
			args: []string{"install", "-r", "requirements.txt"},
			verify: func(t *testing.T, cmd *InstallCommand) {
				if len(cmd.DependencyFiles) != 1 || cmd.DependencyFiles[0] != "requirements.txt" {
					t.Errorf("failed pip requirements parsing: %+v", cmd)
				}
			},
		},
		{
			name:        "unsupported pip uninstall",
			args:        []string{"uninstall", "requests"},
			expectedErr: true,
		},
		{
			name:        "unsupported advanced pip input",
			args:        []string{"install", "git+https://github.com/psf/requests.git"},
			expectedErr: true,
		},
		{
			name:        "unsupported advanced pip flag",
			args:        []string{"install", "--index-url", "https://custom.index/simple", "requests"},
			expectedErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := ParsePip(tc.args)
			if tc.expectedErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.verify(t, cmd)
		})
	}
}

func TestParsePythonPipCommand(t *testing.T) {
	cmd, err := ParseCommand("python", []string{"-m", "pip", "install", "requests"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.PackageManager != "python-pip" || len(cmd.Packages) != 1 || cmd.Packages[0].Name != "requests" {
		t.Errorf("failed python -m pip parsing: %+v", cmd)
	}

	_, err = ParseCommand("python", []string{"run.py"})
	if err == nil {
		t.Fatal("expected error for python run.py")
	}
}

func TestVersionCleaningHelper(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.7.9", "1.7.9"},
		{"^1.7.9", "1.7.9"},
		{"~2.3.0", "2.3.0"},
		{">=1.2.0", "1.2.0"},
		{"<=1.2.0", "1.2.0"},
		{"", ""},
		{">=1.0.0 <2.0.0", ""},
	}

	for _, tc := range tests {
		if got := cleanVersionSpecifier(tc.input); got != tc.expected {
			t.Errorf("cleanVersionSpecifier(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestRedactCommand(t *testing.T) {
	cmd := []string{"npm", "install", "--_auth=xyz123", "--token", "secret-token-here", "axios"}
	redacted := RedactCommand(cmd)

	expected := []string{"npm", "install", "--_auth=[REDACTED]", "--token", "[REDACTED]", "axios"}
	if len(redacted) != len(expected) {
		t.Fatalf("expected len %d, got %d", len(expected), len(redacted))
	}
	for i, v := range redacted {
		if v != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], v)
		}
	}

	url := "https://user:pass123@registry.npmjs.org/"
	redactedURL := RedactString(url)
	if !strings.Contains(redactedURL, "https://[REDACTED]@") {
		t.Errorf("failed URL basic auth redaction: %s", redactedURL)
	}
}

type mockExecutor struct {
	resolvedPm string
	executed   bool
	execArgs   []string
}

func (m *mockExecutor) Resolve(pm string, pol policy.Policy) (string, error) {
	m.resolvedPm = pm
	return "/bin/" + pm, nil
}

func (m *mockExecutor) Execute(ctx context.Context, binary string, args []string, env []string, cwd string) (int, error) {
	m.executed = true
	m.execArgs = args
	return 0, nil
}

func TestRunInterceptBypassesWhenDisabled(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	err := os.WriteFile(policyPath, []byte("install_interception:\n  enabled: false\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	mockExec := &mockExecutor{}
	err = RunIntercept(context.Background(), "npm", []string{"install", "axios", "--policy", policyPath}, mockExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mockExec.executed {
		t.Error("expected package manager to be executed directly when disabled")
	}
}

func TestRunInterceptPreventsSelfRecursion(t *testing.T) {
	t.Setenv("PKGSAFE_INTERCEPT_ACTIVE", "1")
	mockExec := &mockExecutor{}
	err := RunIntercept(context.Background(), "npm", []string{"install", "axios"}, mockExec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mockExec.executed {
		t.Error("expected execution to proceed directly when active env var is set")
	}
}

func TestAuditLogWriting(t *testing.T) {
	tmp := t.TempDir()
	pol := policy.Default()
	pol.InstallInterception.AuditLogPath = filepath.Join(tmp, "audit.log")

	entry := AuditEntry{
		Command:         "npm install axios --token=123",
		Ecosystem:       "npm",
		Mode:            "warn",
		InstallExecuted: true,
	}

	err := LogAudit(pol, entry)
	if err != nil {
		t.Fatalf("failed to log audit: %v", err)
	}

	content, err := os.ReadFile(pol.InstallInterception.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}

	var loaded AuditEntry
	err = json.Unmarshal(content, &loaded)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(loaded.Command, "[REDACTED]") {
		t.Errorf("expected redacted command, got %s", loaded.Command)
	}
}

func TestCanProceedOverrides(t *testing.T) {
	pol := policy.Default()
	pol.InstallInterception.AllowForceRiskAccept = true
	pol.InstallInterception.ForceRiskAcceptRequiresReason = true
	pol.InstallInterception.BlockKnownMalwareAlways = true

	results := []types.ScanResult{
		{
			Package:  types.PackageIdentity{Ecosystem: "npm", Name: "suspicious", Version: "1.0.0"},
			Decision: types.DecisionBlock,
			Reasons: []types.Reason{
				{ID: "known_malware_indicator", Severity: "critical", Description: "known malware"},
			},
		},
	}

	// 1. Block decision without override -> fail
	proceed, _, code := CanProceed(results, types.DecisionBlock, SafetyFlags{}, pol)
	if proceed || code != ExitBlocked {
		t.Errorf("expected block to fail without override, got proceed=%v code=%d", proceed, code)
	}

	// 2. Block decision with override but empty reason -> fail
	proceed, _, code = CanProceed(results, types.DecisionBlock, SafetyFlags{ForceRiskAccept: true}, pol)
	if proceed || code != ExitBlocked {
		t.Errorf("expected block to fail with override but no reason, got proceed=%v code=%d", proceed, code)
	}

	// 3. Block decision with override + reason, but contains known malware -> fail (malware block is true)
	proceed, _, code = CanProceed(results, types.DecisionBlock, SafetyFlags{ForceRiskAccept: true, Reason: "testing"}, pol)
	if proceed || code != ExitBlocked {
		t.Errorf("expected block to fail due to malware restriction, got proceed=%v code=%d", proceed, code)
	}

	// 4. If malware bypass is enabled, override should work!
	pol.InstallInterception.BlockKnownMalwareAlways = false
	proceed, _, code = CanProceed(results, types.DecisionBlock, SafetyFlags{ForceRiskAccept: true, Reason: "testing"}, pol)
	if !proceed || code != ExitSuccess {
		t.Errorf("expected override to succeed when malware bypass is allowed, got proceed=%v code=%d", proceed, code)
	}
}

func TestCanProceedAIAndNonInteractiveWarnings(t *testing.T) {
	pol := policy.Default()
	pol.InstallInterception.NonInteractiveWarnBlocksByDefault = true
	pol.InstallInterception.AllowYesOnWarn = true

	results := []types.ScanResult{
		{
			Package:  types.PackageIdentity{Ecosystem: "npm", Name: "suspicious", Version: "1.0.0"},
			Decision: types.DecisionWarn,
		},
	}

	// 1. Non-interactive warning without --yes -> block
	proceed, _, code := CanProceed(results, types.DecisionWarn, SafetyFlags{}, pol)
	if proceed || code != ExitDeclined {
		t.Errorf("expected warning to block in non-interactive mode without --yes, got proceed=%v code=%d", proceed, code)
	}

	// 2. Non-interactive warning with --yes -> proceed
	proceed, _, code = CanProceed(results, types.DecisionWarn, SafetyFlags{Yes: true}, pol)
	if !proceed || code != ExitSuccess {
		t.Errorf("expected warning to succeed in non-interactive mode with --yes, got proceed=%v code=%d", proceed, code)
	}

	// 3. AI agent warning -> block (must require force-risk-accept)
	t.Setenv("PKGSAFE_REQUESTED_BY", "ai_agent")
	defer os.Unsetenv("PKGSAFE_REQUESTED_BY")

	proceed, _, code = CanProceed(results, types.DecisionWarn, SafetyFlags{Yes: true}, pol)
	if proceed || code != ExitBlocked {
		t.Errorf("expected AI agent warning to block even with --yes, got proceed=%v code=%d", proceed, code)
	}

	proceed, _, code = CanProceed(results, types.DecisionWarn, SafetyFlags{ForceRiskAccept: true, Reason: "AI agent override"}, pol)
	if !proceed || code != ExitSuccess {
		t.Errorf("expected AI agent warning to proceed with explicit force-risk-accept override, got proceed=%v code=%d", proceed, code)
	}
}
