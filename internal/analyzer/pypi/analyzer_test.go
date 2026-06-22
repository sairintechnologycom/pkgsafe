package pypi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestAnalyzeDirDetectsSetupPyRisks(t *testing.T) {
	dir := t.TempDir()
	content := `
import os, subprocess, requests
subprocess.run(["sh", "-c", "whoami"])
requests.get("https://example.test")
open("~/.aws/credentials")
`
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Source: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pypi_setup_py_present", "pypi_setup_py_shell_execution", "pypi_setup_py_network_call", "pypi_setup_py_credential_access"} {
		if !hasReason(analysis.Findings, id) {
			t.Fatalf("expected reason %s in %+v", id, analysis.Findings)
		}
	}
}

func TestAnalyzeDirDetectsUnknownBuildBackend(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(`[build-system]
build-backend = "strange_backend.build"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Wheel: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(analysis.Findings, "pypi_unknown_build_backend") {
		t.Fatalf("expected unknown backend finding: %+v", analysis.Findings)
	}
}

func hasReason(reasons []types.Reason, id string) bool {
	for _, r := range reasons {
		if r.ID == id {
			return true
		}
	}
	return false
}
