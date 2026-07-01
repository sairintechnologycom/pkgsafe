package validation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestValidateRealRepoCountsAndNoExpectation(t *testing.T) {
	dir := t.TempDir()
	deps := []types.Dependency{
		{Ecosystem: "npm", Name: "lodash", Direct: true, DependencyType: "production"},
		{Ecosystem: "npm", Name: "left-pad", Direct: false, DependencyType: "transitive"},
		{Ecosystem: "npm", Name: "react", Direct: true, DependencyType: "source-import"},
		{Name: ""}, // empty entries are ignored
	}
	v := validateRealRepo(RealRepoSpec{Name: "repo", Path: dir, ExpectedNoFalseBlock: true}, deps, 42, false)
	if v.TotalDependencies != 3 {
		t.Errorf("total deps = %d, want 3", v.TotalDependencies)
	}
	if v.DirectDependencies != 1 { // source-import excluded from direct count
		t.Errorf("direct deps = %d, want 1", v.DirectDependencies)
	}
	if v.ScanDurationMs != 42 {
		t.Errorf("duration = %d, want 42", v.ScanDurationMs)
	}
	if v.ExpectedDecision != "" {
		t.Errorf("no expectation file: expected decision should be empty, got %q", v.ExpectedDecision)
	}
	if v.FalseWarn || v.FalseBlock {
		t.Error("no expectation file: must not annotate false warn/block")
	}
}

func TestValidateRealRepoExpectationFileLoads(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".pkgsafe-benchmark.json"),
		[]byte(`{"name":"repo","path":".","repo_type":"npm-simple-app","ecosystems":["npm"],"expected_min_direct_dependencies":5,"expected_no_false_block":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	exp, ok := loadRepoExpectation(dir)
	if !ok {
		t.Fatal("expected expectation file to load")
	}
	if exp.ExpectedMinDirectDependencies != 5 || !exp.ExpectedNoFalseBlock {
		t.Errorf("parsed expectation = %+v", exp)
	}

	// A repo with fewer deps than expected should be annotated (but, without a
	// package.json, no decision is graded so no false warn/block).
	v := validateRealRepo(exp, []types.Dependency{{Name: "a", Direct: true}}, 1, false)
	foundShortfall := false
	for _, d := range v.Details {
		if d == "expected >= 5 direct dependencies, found 1" {
			foundShortfall = true
		}
	}
	if !foundShortfall {
		t.Errorf("expected dependency-shortfall annotation, got %v", v.Details)
	}
}
