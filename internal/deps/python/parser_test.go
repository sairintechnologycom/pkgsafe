package python

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRequirementsPinnedUnpinnedAndRecursive(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "dev.txt")
	root := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(child, []byte("flask>=2.0,<3.0\n-r requirements.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte(`
# comment
requests==2.31.0
pandas[performance]==2.2.0
numpy
--extra-index-url https://example.test/simple
-r dev.txt
`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := ParseRequirementsFile(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
	}
	if got["requests"].Version != "2.31.0" || !got["requests"].Pinned {
		t.Fatalf("requests pin not parsed: %+v", got["requests"])
	}
	if got["pandas"].Version != "2.2.0" {
		t.Fatalf("pandas extras pin not parsed: %+v", got["pandas"])
	}
	if got["numpy"].Pinned {
		t.Fatalf("numpy should be unpinned: %+v", got["numpy"])
	}
	if got["flask"].Pinned || got["flask"].Specifier != ">=2.0,<3.0" {
		t.Fatalf("flask range not parsed: %+v", got["flask"])
	}
}

func TestParsePyprojectProjectAndPoetryDependencies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pyproject.toml")
	if err := os.WriteFile(path, []byte(`
[project]
dependencies = [
  "requests>=2.31.0",
  "pydantic==2.7.0",
]

[project.optional-dependencies]
dev = [
  "pytest",
]

[tool.poetry.dependencies]
python = "^3.11"
flask = "^2.3.0"

[tool.poetry.group.dev.dependencies]
ruff = "^0.5.0"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := ParsePyprojectFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
	}
	if got["pydantic"].Version != "2.7.0" {
		t.Fatalf("pydantic pin not parsed: %+v", got["pydantic"])
	}
	if got["pytest"].Name != "pytest" {
		t.Fatalf("optional dependency not parsed: %+v", got)
	}
	if got["flask"].Specifier != ">=2.3.0" {
		t.Fatalf("poetry dependency not parsed: %+v", got["flask"])
	}
	if got["ruff"].Specifier != ">=0.5.0" {
		t.Fatalf("poetry group dependency not parsed: %+v", got["ruff"])
	}
}
