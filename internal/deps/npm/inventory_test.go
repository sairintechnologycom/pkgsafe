package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
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

func TestScanInventoryPackageJSONDirectDependencyTypes(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, tmp, "package.json", `{
  "dependencies": {"prod-pkg": "^1.0.0"},
  "devDependencies": {"dev-pkg": "^1.0.0"},
  "peerDependencies": {"peer-pkg": "^1.0.0"},
  "optionalDependencies": {"optional-pkg": "^1.0.0"},
  "bundledDependencies": ["bundled-only", "prod-pkg"],
  "bundleDependencies": ["bundle-only"]
}`)

	deps, err := ScanInventory(tmp)
	if err != nil {
		t.Fatal(err)
	}

	assertDep(t, deps, "prod-pkg", "bundled", "package.json", true, false, false)
	assertDep(t, deps, "dev-pkg", "dev", "package.json", true, true, false)
	assertDep(t, deps, "peer-pkg", "peer", "package.json", true, false, false)
	assertDep(t, deps, "optional-pkg", "optional", "package.json", true, false, true)
	assertDep(t, deps, "bundled-only", "bundled", "package.json", true, false, false)
	assertDep(t, deps, "bundle-only", "bundled", "package.json", true, false, false)
}

func TestScanInventoryWorkspacePackageDependenciesPreserveSource(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, tmp, "package.json", `{
  "workspaces": ["packages/*"],
  "dependencies": {"root-pkg": "^1.0.0"}
}`)
	writeFile(t, tmp, "packages/app/package.json", `{
  "dependencies": {"workspace-prod": "^1.0.0"},
  "devDependencies": {"workspace-dev": "^1.0.0"}
}`)

	deps, err := ScanInventory(tmp)
	if err != nil {
		t.Fatal(err)
	}

	assertDep(t, deps, "root-pkg", "production", "package.json", true, false, false)
	assertDep(t, deps, "workspace-prod", "production", "packages/app/package.json", true, false, false)
	assertDep(t, deps, "workspace-dev", "dev", "packages/app/package.json", true, true, false)
}

func TestScanInventoryScopedAliasAndLocalSpecs(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, tmp, "package.json", `{
  "dependencies": {
    "@scope/pkg": "^1.0.0",
    "alias-name": "npm:real-package@1.0.0",
    "file-dep": "file:../file-dep",
    "workspace-dep": "workspace:*",
    "link-dep": "link:../link-dep"
  }
}`)

	deps, err := ScanInventory(tmp)
	if err != nil {
		t.Fatal(err)
	}

	assertDep(t, deps, "@scope/pkg", "production", "package.json", true, false, false)
	assertVersionRange(t, deps, "alias-name", "npm:real-package@1.0.0")
	assertVersionRange(t, deps, "file-dep", "file:../file-dep")
	assertVersionRange(t, deps, "workspace-dep", "workspace:*")
	assertVersionRange(t, deps, "link-dep", "link:../link-dep")
}

func TestScanInventoryPackageLockDirectMapping(t *testing.T) {
	tests := []struct {
		name     string
		lockJSON string
	}{
		{
			name: "v1 top-level direct",
			lockJSON: `{
  "lockfileVersion": 1,
  "dependencies": {
    "direct-pkg": {
      "version": "1.0.0",
      "dependencies": {
        "nested-pkg": {"version": "2.0.0"}
      }
    }
  }
}`,
		},
		{
			name: "v2 root package direct",
			lockJSON: `{
  "lockfileVersion": 2,
  "packages": {
    "": {"dependencies": {"direct-pkg": "^1.0.0"}},
    "node_modules/direct-pkg": {"version": "1.0.0", "dependencies": {"nested-pkg": "^2.0.0"}},
    "node_modules/nested-pkg": {"version": "2.0.0"}
  }
}`,
		},
		{
			name: "v3 root dev optional direct",
			lockJSON: `{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "devDependencies": {"direct-pkg": "^1.0.0"},
      "optionalDependencies": {"optional-pkg": "^2.0.0"}
    },
    "node_modules/direct-pkg": {"version": "1.0.0"},
    "node_modules/optional-pkg": {"version": "2.0.0"}
  }
}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			writeFile(t, tmp, "package-lock.json", tc.lockJSON)

			deps, err := ScanInventory(tmp)
			if err != nil {
				t.Fatal(err)
			}

			switch tc.name {
			case "v1 top-level direct":
				assertDep(t, deps, "direct-pkg", "production", "package-lock.json", true, false, false)
				assertDep(t, deps, "nested-pkg", "transitive", "package-lock.json", false, false, false)
			case "v2 root package direct":
				assertDep(t, deps, "direct-pkg", "production", "package-lock.json", true, false, false)
				assertDep(t, deps, "nested-pkg", "transitive", "package-lock.json", false, false, false)
			case "v3 root dev optional direct":
				assertDep(t, deps, "direct-pkg", "dev", "package-lock.json", true, true, false)
				assertDep(t, deps, "optional-pkg", "optional", "package-lock.json", true, false, true)
			}
		})
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func assertDep(t *testing.T, deps []types.Dependency, name, depType, sourceFile string, direct, dev, optional bool) {
	t.Helper()
	for _, dep := range deps {
		if dep.Name == name && dep.DependencyType == depType && dep.SourceFile == sourceFile && dep.Direct == direct && dep.Dev == dev && dep.Optional == optional {
			return
		}
	}
	t.Fatalf("missing dependency %s type=%s source=%s direct=%t dev=%t optional=%t in %+v", name, depType, sourceFile, direct, dev, optional, deps)
}

func assertVersionRange(t *testing.T, deps []types.Dependency, name, versionRange string) {
	t.Helper()
	for _, dep := range deps {
		if dep.Name == name && dep.VersionRange == versionRange && dep.DependencyType == "production" && dep.Direct {
			return
		}
	}
	t.Fatalf("missing dependency %s with version range %q in %+v", name, versionRange, deps)
}
