package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
