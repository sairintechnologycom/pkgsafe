package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestParseImportPackage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		{"lodash", "lodash", true},
		{"lodash/fp", "lodash", true},
		{"@scope/pkg", "@scope/pkg", true},
		{"@scope/pkg/subpath", "@scope/pkg", true},
		{"./relative", "", false},
		{"../relative", "", false},
		{"/absolute", "", false},
		{"fs", "", false},
		{"path", "", false},
		{"node:crypto", "", false},
		{"", "", false},
	}

	for _, tc := range tests {
		got, ok := parseImportPackage(tc.input)
		if ok != tc.ok || (ok && got != tc.expected) {
			t.Errorf("parseImportPackage(%q) = (%q, %t), expected (%q, %t)", tc.input, got, ok, tc.expected, tc.ok)
		}
	}
}

func TestExtractCallArguments(t *testing.T) {
	content := `
		require("pkg-a");
		import('pkg-b');
		const x = require(varName);
		import(dynVar);
		require("pkg-c" + "pkg-d");
	`
	expected := []string{
		`"pkg-a"`,
		`'pkg-b'`,
		`varName`,
		`dynVar`,
		`"pkg-c" + "pkg-d"`,
	}

	got := extractCallArguments(content)
	if len(got) != len(expected) {
		t.Fatalf("extractCallArguments returned %d args, expected %d", len(got), len(expected))
	}
	for i, v := range got {
		if v != expected[i] {
			t.Errorf("arg[%d] = %q, expected %q", i, v, expected[i])
		}
	}
}

func TestCheckMismatches(t *testing.T) {
	// 1. Undeclared import
	deps1 := []types.Dependency{
		{SourceFile: "package.json", Name: "", DependencyType: "package.json"}, // pseudo-dep
		{SourceFile: "index.js", Name: "lodash", DependencyType: "source-import"},
	}
	reasons1 := CheckMismatches(deps1)
	if len(reasons1) != 1 || reasons1[0].ID != "undeclared_source_import" {
		t.Errorf("expected undeclared_source_import, got: %+v", reasons1)
	}

	// 2. Transitive dependency direct use
	deps2 := []types.Dependency{
		{SourceFile: "package.json", Name: "", DependencyType: "package.json"},
		{SourceFile: "package-lock.json", Name: "", DependencyType: "package-lock.json"},
		{SourceFile: "package-lock.json", Name: "lodash", DependencyType: "transitive", Direct: false},
		{SourceFile: "index.js", Name: "lodash", DependencyType: "source-import"},
	}
	reasons2 := CheckMismatches(deps2)
	if len(reasons2) != 1 || reasons2[0].ID != "direct_use_of_transitive_dependency" {
		t.Errorf("expected direct_use_of_transitive_dependency, got: %+v", reasons2)
	}

	// 3. Unused declared dependency
	deps3 := []types.Dependency{
		{SourceFile: "package.json", Name: "", DependencyType: "package.json"},
		{SourceFile: "package.json", Name: "express", DependencyType: "production"},
	}
	reasons3 := CheckMismatches(deps3)
	if len(reasons3) != 1 || reasons3[0].ID != "unused_declared_dependency" {
		t.Errorf("expected unused_declared_dependency, got: %+v", reasons3)
	}

	// 4. Unresolved dynamic import
	deps4 := []types.Dependency{
		{SourceFile: "index.js", Name: "varName", DependencyType: "unresolved-dynamic-import"},
	}
	reasons4 := CheckMismatches(deps4)
	if len(reasons4) != 1 || reasons4[0].ID != "unresolved_dynamic_import" {
		t.Errorf("expected unresolved_dynamic_import, got: %+v", reasons4)
	}
}

func TestScanInventory_MalformedAndEmpty(t *testing.T) {
	tmp, err := os.MkdirTemp("", "pkgsafe-inventory-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// Write empty package.json
	err = os.WriteFile(filepath.Join(tmp, "package.json"), []byte("{}"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	deps, err := ScanInventory(tmp)
	if err != nil {
		t.Fatalf("ScanInventory failed on empty package.json: %v", err)
	}
	// Should return 1 pseudo-dependency for package.json
	if len(deps) != 1 || deps[0].DependencyType != "package.json" {
		t.Errorf("expected only 1 package.json pseudo-dependency, got: %+v", deps)
	}

	// Write malformed package.json
	err = os.WriteFile(filepath.Join(tmp, "package.json"), []byte("{malformed}"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	deps, err = ScanInventory(tmp)
	if err != nil {
		t.Fatalf("ScanInventory failed on malformed package.json: %v", err)
	}
}
