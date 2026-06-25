package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/api"
)

func TestReorderFlagsAllowsTrailingCommandFlags(t *testing.T) {
	got := reorderFlags([]string{"is-number", "--version", "7.0.0", "--json"})
	want := []string{"--version", "7.0.0", "--json", "is-number"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reorderFlags() = %v, want %v", got, want)
	}
}

func TestCIScanCommandRouting(t *testing.T) {
	err := run([]string{"ci", "scan", "--lockfile", "nonexistent-lockfile-for-main-test.json"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	eErr, ok := err.(exitError)
	if !ok {
		t.Fatalf("expected exitError, got %T", err)
	}
	if eErr.code != 5 {
		t.Fatalf("expected exit code 5 (lockfile error), got %d", eErr.code)
	}
}

func TestCIScanUsageError(t *testing.T) {
	err := run([]string{"ci", "scan", "--lockfile", "nonexistent-lockfile-for-main-test.json", "--fail-on", "invalid-value"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	eErr, ok := err.(exitError)
	if !ok {
		t.Fatalf("expected exitError, got %T", err)
	}
	if eErr.code != 2 {
		t.Fatalf("expected exit code 2 (usage error), got %d", eErr.code)
	}
}

func TestReportCommandCLI(t *testing.T) {
	tmp, err := os.MkdirTemp("", "cli-report-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tmp)

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	// Create mock policy pack
	packDir := filepath.Join(tmp, ".pkgsafe", "policy-packs", "enterprise-standard", "1.0.0")
	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatalf("mkdir policy pack: %v", err)
	}
	metaJSON := `{"name":"enterprise-standard","version":"2026.06.01","owner":"Platform Engineering","expires_at":"2027-12-31T23:59:59Z","compatibility":{"min_pkgsafe_version":"0.1.0"}}`
	if err := os.WriteFile(filepath.Join(packDir, "metadata.json"), []byte(metaJSON), 0644); err != nil {
		t.Fatalf("write metadata.json: %v", err)
	}
	policyYAML := `mode: warn
thresholds:
  allow_max_score: 29
  warn_max_score: 69
  block_min_score: 70`
	if err := os.WriteFile(filepath.Join(packDir, "policy.yaml"), []byte(policyYAML), 0644); err != nil {
		t.Fatalf("write policy.yaml: %v", err)
	}

	// 1. Generate Report
	outPath := filepath.Join(tmp, "report")
	err = run([]string{"report", "generate", "--repo", ".", "--output", outPath, "--format", "all"})
	if err != nil {
		t.Fatalf("pkgsafe report generate failed: %v", err)
	}

	// Verify files generated
	for _, ext := range []string{".md", ".json", ".html"} {
		if _, err := os.Stat(outPath + ext); err != nil {
			t.Errorf("expected report file %s to be created", outPath+ext)
		}
	}

	// 2. Policy Report
	policyOut := filepath.Join(tmp, "policy.md")
	err = run([]string{"report", "policy", "--output", policyOut})
	if err != nil {
		t.Fatalf("pkgsafe report policy failed: %v", err)
	}
	if _, err := os.Stat(policyOut); err != nil {
		t.Errorf("expected policy report to be created")
	}

	// 3. CI Report
	ciJSON := filepath.Join(tmp, "ci.json")
	ciEvidence := filepath.Join(tmp, "ci-evidence.md")
	fakeCIResult := `{"schema_version":"1.0","tool":"pkgsafe","baseline":"main","summary":{"packages_scanned":1,"allow":1,"warn":0,"block":0},"findings":[]}`
	if err := os.WriteFile(ciJSON, []byte(fakeCIResult), 0644); err != nil {
		t.Fatalf("write fake CI results: %v", err)
	}
	err = run([]string{"report", "ci", "--input", ciJSON, "--output", ciEvidence})
	if err != nil {
		t.Fatalf("pkgsafe report ci failed: %v", err)
	}
	if _, err := os.Stat(ciEvidence); err != nil {
		t.Errorf("expected CI gate report to be created")
	}
}

func TestMCPCommandCleanStdout(t *testing.T) {
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	inW.Close() // Close writer immediately so reading from inR returns EOF
	defer inR.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	os.Stdin = inR
	os.Stdout = w

	// Run command
	err = run([]string{"mcp", "serve"})
	w.Close()
	if err != nil {
		t.Fatalf("pkgsafe mcp serve failed: %v", err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}

	if buf.Len() > 0 {
		t.Errorf("expected no output on stdout for empty input, got %q", buf.String())
	}
}

func TestServeAPICommand(t *testing.T) {
	// Stub apiServeFunc
	oldAPIServe := apiServeFunc
	defer func() { apiServeFunc = oldAPIServe }()

	var calledCfg api.Config
	var called bool

	apiServeFunc = func(cfg api.Config) error {
		called = true
		calledCfg = cfg
		return nil
	}

	tests := []struct {
		name     string
		args     []string
		wantPort string
		wantTok  string
		wantPol  string
		wantMode string
		wantOff  bool
	}{
		{
			name:     "default values",
			args:     []string{"serve-api"},
			wantPort: "8080",
			wantTok:  "",
			wantPol:  "",
			wantMode: "",
			wantOff:  false,
		},
		{
			name:     "custom flags",
			args:     []string{"serve-api", "--port", "9090", "--token", "test-token", "--policy", "/path/to/policy.yaml", "--mode", "block", "--offline"},
			wantPort: "9090",
			wantTok:  "test-token",
			wantPol:  "/path/to/policy.yaml",
			wantMode: "block",
			wantOff:  true,
		},
		{
			name:     "flags after command",
			args:     []string{"serve-api", "--offline", "--port=9091", "--token=xyz"},
			wantPort: "9091",
			wantTok:  "xyz",
			wantPol:  "",
			wantMode: "",
			wantOff:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			calledCfg = api.Config{}
			err := run(tt.args)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if !called {
				t.Fatal("expected api.Serve to be called, but it was not")
			}
			if calledCfg.Port != tt.wantPort {
				t.Errorf("Port = %q, want %q", calledCfg.Port, tt.wantPort)
			}
			if calledCfg.Token != tt.wantTok {
				t.Errorf("Token = %q, want %q", calledCfg.Token, tt.wantTok)
			}
			if calledCfg.DefaultPolicy != tt.wantPol {
				t.Errorf("DefaultPolicy = %q, want %q", calledCfg.DefaultPolicy, tt.wantPol)
			}
			if calledCfg.DefaultMode != tt.wantMode {
				t.Errorf("DefaultMode = %q, want %q", calledCfg.DefaultMode, tt.wantMode)
			}
			if calledCfg.Offline != tt.wantOff {
				t.Errorf("Offline = %v, want %v", calledCfg.Offline, tt.wantOff)
			}
			if calledCfg.Version != version {
				t.Errorf("Version = %q, want %q", calledCfg.Version, version)
			}
			if calledCfg.Commit != commit {
				t.Errorf("Commit = %q, want %q", calledCfg.Commit, commit)
			}
		})
	}
}

