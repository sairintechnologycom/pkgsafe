package pypi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
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

func TestAnalyzeDirDetectsPythonStaticRiskPatterns(t *testing.T) {
	dir := t.TempDir()
	scriptsDir := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, "install-helper.py"), []byte(`
import base64
import os
import requests
payload = base64.b64decode("cHJpbnQoMSk=")
exec(payload)
requests.get("http://169.254.169.254/latest/meta-data/")
open(os.path.expanduser("~/.ssh/id_rsa"))
os.environ.get("AWS_SECRET_ACCESS_KEY")
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "native_ext.so"), []byte("native"), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Wheel: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"pypi_eval_exec_usage",
		"pypi_base64_exec_payload",
		"pypi_network_call",
		"pypi_credential_path_access",
		"pypi_env_secret_access",
		"pypi_cloud_metadata_access",
		"pypi_native_extension",
	} {
		if !hasReason(analysis.Findings, id) {
			t.Fatalf("expected reason %s in %+v", id, analysis.Findings)
		}
	}
	if !analysis.Artifact.NativeExtension {
		t.Fatal("expected native extension artifact metadata")
	}
	if analysis.Result.Decision != types.DecisionBlock {
		t.Fatalf("expected critical static findings to block, got %s", analysis.Result.Decision)
	}
}

func TestAnalyzeDirDoesNotScoreOrdinaryLibrarySourceAsInstallBehavior(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client.py"), []byte(`
import os
import requests

def fetch(url):
    return requests.get(url, headers={"authorization": os.environ.get("TOKEN", "")})
`), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeDir(dir, Metadata{Name: "network-lib", Version: "1.0.0", Wheel: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pypi_network_call", "pypi_env_secret_access"} {
		if hasReason(analysis.Findings, id) {
			t.Fatalf("ordinary library source should not score %s: %+v", id, analysis.Findings)
		}
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
