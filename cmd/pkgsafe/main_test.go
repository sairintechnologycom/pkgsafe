package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/api"
	"github.com/sairintechnologycom/pkgsafe/internal/validation"
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

func TestBetaEvidenceRenderAndJSONDoNotLeakSecrets(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SHOULD_NOT_LEAK_TEST_SECRET")
	evidence := betaEvidenceReport{
		GeneratedAt: "2026-06-27T00:00:00Z",
		ProductionReadiness: validation.ProductionReadinessReport{
			CurrentStage:                    "PRIVATE_BETA_READY",
			PrivateBetaReady:                true,
			GAReady:                         false,
			RealRepoValidationCount:         0,
			RequiredRealRepoValidationCount: 15,
			GABlockers:                      []string{"real_repo_validation_count below GA threshold"},
		},
		BenchmarkSummary: validation.BenchmarkMetrics{},
		EcosystemDepth: map[string]string{
			"npm":   "strongest private-beta coverage",
			"pypi":  "early coverage; not npm-equivalent",
			"go":    "metadata and OSV-oriented; not npm-equivalent",
			"cargo": "metadata and OSV-oriented; not npm-equivalent",
		},
		BehaviorModeSummary:   "behavior analysis disabled by default",
		SecurityGateStatus:    map[string]string{"rollout_readiness": "pass"},
		ReleaseArtifactStatus: map[string]string{"sbom": "present"},
		KnownLimitations:      []string{"isolated behavior backend is experimental and Linux-only"},
		Recommendation:        "PRIVATE_BETA_READY",
	}
	md := []byte(renderBetaEvidenceMarkdown(evidence))
	if !bytes.Contains(md, []byte("PkgSafe Private Beta Evidence")) {
		t.Fatalf("markdown evidence missing title:\n%s", string(md))
	}
	if bytes.Contains(md, []byte("SHOULD_NOT_LEAK_TEST_SECRET")) {
		t.Fatal("markdown evidence leaked environment secret")
	}
	rawJSON, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawJSON, []byte("SHOULD_NOT_LEAK_TEST_SECRET")) {
		t.Fatal("json evidence leaked environment secret")
	}
	var decoded map[string]any
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["recommendation"] == "" {
		t.Fatal("json evidence missing recommendation")
	}
}

func TestWriteBetaEvidenceZip(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "pkgsafe-private-beta-evidence.zip")
	evidence := betaEvidenceReport{
		GeneratedAt: "2026-06-27T00:00:00Z",
		ProductionReadiness: validation.ProductionReadinessReport{
			CurrentStage:                    "PRIVATE_BETA_READY",
			PrivateBetaReady:                true,
			GAReady:                         false,
			RealRepoValidationCount:         1,
			RequiredRealRepoValidationCount: 15,
		},
		BenchmarkReport: validation.BenchmarkReport{
			RepoValidations: []validation.RepoValidation{
				{Name: "repo-one", Path: "/tmp/repo-one", ScanCompleted: true, JSONOutputGenerated: true},
			},
		},
		BenchmarkSummary: validation.BenchmarkMetrics{RealRepoValidationCount: 1},
		EcosystemDepth: map[string]string{
			"npm": "strongest private-beta coverage",
		},
		KnownLimitations: []string{"real repo validation count is below GA threshold"},
		Recommendation:   "PRIVATE_BETA_READY",
	}
	if err := writeBetaEvidenceZip(out, evidence); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	seen := map[string]bool{}
	for _, f := range zr.File {
		seen[f.Name] = true
	}
	for _, want := range []string{
		"pkgsafe-private-beta-evidence/manifest.json",
		"pkgsafe-private-beta-evidence/repo-validation-summary.json",
		"pkgsafe-private-beta-evidence/repo-validation-summary.md",
		"pkgsafe-private-beta-evidence/benchmark-output.json",
		"pkgsafe-private-beta-evidence/production-readiness-output.json",
		"pkgsafe-private-beta-evidence/version-info.json",
		"pkgsafe-private-beta-evidence/policy-used.json",
		"pkgsafe-private-beta-evidence/known-limitations.md",
		"pkgsafe-private-beta-evidence/per-repo/repo-one.json",
	} {
		if !seen[want] {
			t.Fatalf("zip missing %s; saw %#v", want, seen)
		}
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

func TestPolicyTestFixtures(t *testing.T) {
	err := run([]string{"policy", "test", filepath.Join("..", "..", "testdata", "policy-fixtures")})
	if err != nil {
		t.Fatalf("policy test fixtures failed: %v", err)
	}
}

func TestRegistryTestPackageRoutingCLI(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
mode: warn
registries:
  npm:
    company:
      url: "https://npm.company.test/"
      type: private
      enabled: true
      scopes: ["@company"]
    default:
      url: "https://registry.npmjs.org/"
      type: public
      enabled: false
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"registry", "test", "--policy", policyPath, "--ecosystem", "npm", "--package", "@company/api"}); err != nil {
		t.Fatalf("registry package routing test failed: %v", err)
	}
}

func TestReportCommandCLI(t *testing.T) {
	tmp := t.TempDir()

	// 1. Generate Report
	outPath := filepath.Join(tmp, "report")
	err := run([]string{"report", "generate", "--repo", ".", "--output", outPath, "--format", "all"})
	if err != nil {
		t.Fatalf("pkgsafe report generate failed: %v", err)
	}

	// Verify files generated
	for _, ext := range []string{".md", ".json", ".html"} {
		if _, err := os.Stat(outPath + ext); err != nil {
			t.Errorf("expected report file %s to be created", outPath+ext)
		}
	}

	// 2. Policy Report is private-enterprise only in the public repo.
	if err := run([]string{"report", "policy", "--output", filepath.Join(tmp, "policy.md")}); err == nil {
		t.Fatalf("expected pkgsafe report policy to be rejected in public build")
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

func TestScanGoAndCargoDepsCommands(t *testing.T) {
	tmp, err := os.MkdirTemp("", "go-cargo-test")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Create dummy go.mod
	goModContent := `module testapp

go 1.20

require (
	github.com/example/foo v1.0.0
)
`
	goModPath := filepath.Join(tmp, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// Create dummy Cargo.lock
	cargoLockContent := `[[package]]
name = "test-crate"
version = "0.2.0"
`
	cargoLockPath := filepath.Join(tmp, "Cargo.lock")
	if err := os.WriteFile(cargoLockPath, []byte(cargoLockContent), 0644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	// 1. Run scan-go-deps with --offline flag
	err = run([]string{"scan-go-deps", goModPath, "--offline"})
	if err != nil {
		t.Errorf("scan-go-deps failed: %v", err)
	}

	// 2. Run scan-go-deps with --json and --offline
	err = run([]string{"scan-go-deps", goModPath, "--offline", "--json"})
	if err != nil {
		t.Errorf("scan-go-deps --json failed: %v", err)
	}

	// 3. Test missing positional argument for scan-go-deps
	err = run([]string{"scan-go-deps", "--offline"})
	if err == nil {
		t.Errorf("expected error for missing positional argument in scan-go-deps, got nil")
	}

	// 4. Run scan-cargo-deps with --offline
	err = run([]string{"scan-cargo-deps", cargoLockPath, "--offline"})
	if err != nil {
		t.Errorf("scan-cargo-deps failed: %v", err)
	}

	// 5. Run scan-cargo-deps with --json and --offline
	err = run([]string{"scan-cargo-deps", cargoLockPath, "--offline", "--json"})
	if err != nil {
		t.Errorf("scan-cargo-deps --json failed: %v", err)
	}

	// 6. Test missing positional argument for scan-cargo-deps
	err = run([]string{"scan-cargo-deps", "--offline"})
	if err == nil {
		t.Errorf("expected error for missing positional argument in scan-cargo-deps, got nil")
	}
}
