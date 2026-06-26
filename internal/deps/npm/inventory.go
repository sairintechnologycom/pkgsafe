package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

var (
	// Matches: import x from "pkg", import {x} from "pkg", import * as x from "pkg", export * from "pkg"
	importFromRegex = regexp.MustCompile(`\b(?:import|export)\s+[^;]*?\bfrom\s+['"]([^'"]+)['"]`)
	// Matches: import "pkg"
	importSideRegex = regexp.MustCompile(`\bimport\s+['"]([^'"]+)['"]`)

	nodeBuiltins = map[string]bool{
		"assert":         true,
		"async_hooks":    true,
		"buffer":         true,
		"child_process":  true,
		"cluster":        true,
		"console":        true,
		"constants":      true,
		"crypto":         true,
		"dgram":          true,
		"dns":            true,
		"domain":         true,
		"events":         true,
		"fs":             true,
		"http":           true,
		"http2":          true,
		"https":          true,
		"inspector":      true,
		"module":         true,
		"net":            true,
		"os":             true,
		"path":           true,
		"perf_hooks":     true,
		"process":        true,
		"punycode":       true,
		"querystring":    true,
		"readline":       true,
		"repl":           true,
		"stream":         true,
		"string_decoder": true,
		"sys":            true,
		"timers":         true,
		"tls":            true,
		"trace_events":   true,
		"tty":            true,
		"url":            true,
		"util":           true,
		"v8":             true,
		"vm":             true,
		"wasi":           true,
		"worker_threads": true,
		"zlib":           true,
	}
)

type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	BundledDependencies  any               `json:"bundledDependencies"`
	BundleDependencies   any               `json:"bundleDependencies"`
	Workspaces           any               `json:"workspaces"`
}

type packageLock struct {
	Name            string                           `json:"name"`
	Version         string                           `json:"version"`
	LockfileVersion int                              `json:"lockfileVersion"`
	Packages        map[string]packageLockPackage    `json:"packages"`
	Dependencies    map[string]packageLockDependency `json:"dependencies"`
}

type packageLockPackage struct {
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type packageLockDependency struct {
	Version      string                           `json:"version"`
	Dev          bool                             `json:"dev"`
	Optional     bool                             `json:"optional"`
	Requires     map[string]string                `json:"requires"`
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

// ScanInventory walks the repository path and gathers all dependencies.
func ScanInventory(repoPath string) ([]types.Dependency, error) {
	var packageJSONPaths []string
	var packageLockPaths []string
	var sourcePaths []string

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "node_modules" || info.Name() == ".git" || info.Name() == "dist" || info.Name() == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		name := info.Name()
		rel, err := filepath.Rel(repoPath, path)
		if err != nil {
			rel = path
		}

		if name == "package.json" {
			packageJSONPaths = append(packageJSONPaths, rel)
		} else if name == "package-lock.json" {
			packageLockPaths = append(packageLockPaths, rel)
		} else if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".jsx") || strings.HasSuffix(name, ".tsx") {
			sourcePaths = append(sourcePaths, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk repository: %w", err)
	}

	var results []types.Dependency
	directDepsMap := make(map[string]string) // package_name -> dependency_type

	// 1. Process package.json files
	for _, relPath := range packageJSONPaths {
		fullPath := filepath.Join(repoPath, relPath)
		b, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("read package.json: %w", err)
		}
		var pj PackageJSON
		if err := json.Unmarshal(b, &pj); err != nil {
			continue
		}

		bundledNames := parseBundled(pj.BundledDependencies)
		if len(bundledNames) == 0 {
			bundledNames = parseBundled(pj.BundleDependencies)
		}
		bundledSet := make(map[string]bool)
		for _, name := range bundledNames {
			bundledSet[name] = true
		}

		addDeps := func(deps map[string]string, depType string) {
			for name, versionRange := range deps {
				actualType := depType
				if bundledSet[name] {
					actualType = "bundled"
				}
				results = append(results, types.Dependency{
					Ecosystem:      "npm",
					Name:           name,
					VersionRange:   versionRange,
					SourceFile:     relPath,
					DependencyType: actualType,
					Direct:         true,
				})
				if current, ok := directDepsMap[name]; !ok || precedence(actualType) > precedence(current) {
					directDepsMap[name] = actualType
				}
			}
		}

		addDeps(pj.Dependencies, "production")
		addDeps(pj.DevDependencies, "dev")
		addDeps(pj.PeerDependencies, "peer")
		addDeps(pj.OptionalDependencies, "optional")

		// Emit a pseudo-dependency to track presence of package.json
		results = append(results, types.Dependency{
			Ecosystem:      "npm",
			Name:           "",
			VersionRange:   "",
			SourceFile:     relPath,
			DependencyType: "package.json",
			Direct:         true,
		})
	}

	// 2. Process package-lock.json files
	for _, relPath := range packageLockPaths {
		fullPath := filepath.Join(repoPath, relPath)
		b, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("read package-lock.json: %w", err)
		}
		var lf packageLock
		if err := json.Unmarshal(b, &lf); err != nil {
			continue
		}

		// Emit a pseudo-dependency to track presence of package-lock.json
		results = append(results, types.Dependency{
			Ecosystem:      "npm",
			Name:           "",
			VersionRange:   "",
			SourceFile:     relPath,
			DependencyType: "package-lock.json",
			Direct:         true,
		})

		if len(lf.Packages) > 0 {
			lockDirectDeps := make(map[string]string)
			for path, pkg := range lf.Packages {
				if path == "" || !strings.HasPrefix(path, "node_modules/") {
					collectDirectDeps(pkg.Dependencies, "production", lockDirectDeps)
					collectDirectDeps(pkg.DevDependencies, "dev", lockDirectDeps)
					collectDirectDeps(pkg.PeerDependencies, "peer", lockDirectDeps)
					collectDirectDeps(pkg.OptionalDependencies, "optional", lockDirectDeps)
				}
			}

			for path, pkg := range lf.Packages {
				if path == "" || !strings.HasPrefix(path, "node_modules/") {
					continue
				}

				name := extractNameFromPath(path)
				if name == "" {
					continue
				}

				depType := "transitive"
				direct := false
				if t, ok := lockDirectDeps[name]; ok {
					depType = t
					direct = true
				} else if t, ok := directDepsMap[name]; ok {
					depType = t
					direct = true
				}

				results = append(results, types.Dependency{
					Ecosystem:      "npm",
					Name:           name,
					VersionRange:   pkg.Version,
					SourceFile:     relPath,
					DependencyType: depType,
					Direct:         direct,
					Dev:            pkg.Dev,
					Optional:       pkg.Optional,
					Resolved:       pkg.Resolved,
					Integrity:      pkg.Integrity,
					PackagePath:    path,
				})
			}
		} else if len(lf.Dependencies) > 0 {
			var v1Out []types.Dependency
			parseLockfileV1Deps(lf.Dependencies, "", directDepsMap, relPath, &v1Out)
			results = append(results, v1Out...)
		}
	}

	// 3. Process source import scanning
	for _, relPath := range sourcePaths {
		fullPath := filepath.Join(repoPath, relPath)
		b, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("read source file: %w", err)
		}
		content := stripComments(string(b))

		importedPkgs := make(map[string]bool)

		// Regex for static imports/exports
		findMatches := func(re *regexp.Regexp) {
			matches := re.FindAllStringSubmatch(content, -1)
			for _, m := range matches {
				if len(m) > 1 {
					pkgPath := m[1]
					if pkg, ok := parseImportPackage(pkgPath); ok {
						importedPkgs[pkg] = true
					}
				}
			}
		}

		findMatches(importFromRegex)
		findMatches(importSideRegex)

		// Function call require(...) or import(...) arguments parsing
		args := extractCallArguments(content)
		for _, arg := range args {
			if isQuoted(arg) {
				cleanPkg := arg[1 : len(arg)-1]
				if pkg, ok := parseImportPackage(cleanPkg); ok {
					importedPkgs[pkg] = true
				}
			} else {
				// Flag unresolved dynamic import
				results = append(results, types.Dependency{
					Ecosystem:      "npm",
					Name:           arg,
					VersionRange:   "",
					SourceFile:     relPath,
					DependencyType: "unresolved-dynamic-import",
					Direct:         true,
				})
			}
		}

		for pkgName := range importedPkgs {
			results = append(results, types.Dependency{
				Ecosystem:      "npm",
				Name:           pkgName,
				VersionRange:   "",
				SourceFile:     relPath,
				DependencyType: "source-import",
				Direct:         true,
			})
		}
	}

	return results, nil
}

func precedence(depType string) int {
	switch depType {
	case "production":
		return 4
	case "dev":
		return 3
	case "peer":
		return 2
	case "optional":
		return 1
	case "bundled":
		return 5
	default:
		return 0
	}
}

func collectDirectDeps(m map[string]string, depType string, dest map[string]string) {
	for name := range m {
		if current, ok := dest[name]; !ok || precedence(depType) > precedence(current) {
			dest[name] = depType
		}
	}
}

func parseBundled(b any) []string {
	if b == nil {
		return nil
	}
	switch val := b.(type) {
	case []any:
		var res []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	case []string:
		return val
	}
	return nil
}

func extractNameFromPath(path string) string {
	if !strings.HasPrefix(path, "node_modules/") {
		return ""
	}
	parts := strings.Split(path, "/")
	n := len(parts)
	if n >= 2 && strings.HasPrefix(parts[n-2], "@") {
		return parts[n-2] + "/" + parts[n-1]
	}
	return parts[n-1]
}

func parseLockfileV1Deps(deps map[string]packageLockDependency, parentPath string, directMap map[string]string, sourceFile string, out *[]types.Dependency) {
	for name, dep := range deps {
		pkgPath := name
		if parentPath != "" {
			pkgPath = parentPath + "/node_modules/" + name
		} else {
			pkgPath = "node_modules/" + name
		}

		depType := "transitive"
		direct := false
		if parentPath == "" {
			if t, ok := directMap[name]; ok {
				depType = t
				direct = true
			}
		}

		d := types.Dependency{
			Ecosystem:      "npm",
			Name:           name,
			VersionRange:   dep.Version,
			SourceFile:     sourceFile,
			DependencyType: depType,
			Direct:         direct,
			Dev:            dep.Dev,
			Optional:       dep.Optional,
			PackagePath:    pkgPath,
		}
		*out = append(*out, d)

		if len(dep.Dependencies) > 0 {
			parseLockfileV1Deps(dep.Dependencies, pkgPath, directMap, sourceFile, out)
		}
	}
}

func stripComments(content string) string {
	singleLine := regexp.MustCompile(`//.*`)
	content = singleLine.ReplaceAllString(content, "")

	multiLine := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	content = multiLine.ReplaceAllString(content, "")

	return content
}

func parseImportPackage(importPath string) (string, bool) {
	importPath = strings.TrimSpace(importPath)
	if importPath == "" {
		return "", false
	}
	if strings.HasPrefix(importPath, ".") || strings.HasPrefix(importPath, "/") || filepath.IsAbs(importPath) {
		return "", false
	}
	if nodeBuiltins[importPath] || strings.HasPrefix(importPath, "node:") {
		return "", false
	}
	if strings.HasPrefix(importPath, "@") {
		parts := strings.Split(importPath, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1], true
		}
		return importPath, true
	}
	parts := strings.Split(importPath, "/")
	return parts[0], true
}

func isQuoted(s string) bool {
	if len(s) < 2 {
		return false
	}
	first := s[0]
	last := s[len(s)-1]
	return (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`')
}

func extractCallArguments(content string) []string {
	var args []string
	idx := 0
	for {
		rIdx := strings.Index(content[idx:], "require(")
		iIdx := strings.Index(content[idx:], "import(")

		target := -1
		if rIdx != -1 && iIdx != -1 {
			if rIdx < iIdx {
				target = idx + rIdx + len("require(")
			} else {
				target = idx + iIdx + len("import(")
			}
		} else if rIdx != -1 {
			target = idx + rIdx + len("require(")
		} else if iIdx != -1 {
			target = idx + iIdx + len("import(")
		} else {
			break
		}

		depth := 1
		start := target
		end := -1
		for i := start; i < len(content); i++ {
			if content[i] == '(' {
				depth++
			} else if content[i] == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end == -1 {
			idx = start
			continue
		}

		argStr := strings.TrimSpace(content[start:end])
		if argStr != "" {
			args = append(args, argStr)
		}
		idx = end + 1
	}
	return args
}

// CheckMismatches runs mismatch checks on a list of dependencies.
func CheckMismatches(deps []types.Dependency) []types.Reason {
	var reasons []types.Reason

	declaredDeps := make(map[string]string)
	declaredPackages := make(map[string]bool)
	hasPackageJSON := false

	importedDeps := make(map[string][]string)
	unresolvedImports := make(map[string][]string)

	lockfileDeps := make(map[string]bool)
	lockfileDirectDeps := make(map[string]string)
	lockfileTransitiveDeps := make(map[string]bool)
	hasLockfile := false

	for _, d := range deps {
		if strings.HasSuffix(d.SourceFile, "package.json") {
			hasPackageJSON = true
			if d.Name != "" && d.DependencyType != "source-import" && d.DependencyType != "transitive" && d.DependencyType != "unresolved-dynamic-import" {
				declaredDeps[d.Name] = d.DependencyType
				declaredPackages[d.Name] = true
			}
		} else if strings.HasSuffix(d.SourceFile, "package-lock.json") {
			hasLockfile = true
			if d.Name != "" {
				lockfileDeps[d.Name] = true
				if d.Direct {
					lockfileDirectDeps[d.Name] = d.DependencyType
				} else {
					lockfileTransitiveDeps[d.Name] = true
				}
			}
		} else {
			if d.DependencyType == "source-import" {
				importedDeps[d.Name] = append(importedDeps[d.Name], d.SourceFile)
			} else if d.DependencyType == "unresolved-dynamic-import" {
				unresolvedImports[d.Name] = append(unresolvedImports[d.Name], d.SourceFile)
			}
		}
	}

	for name, files := range unresolvedImports {
		reasons = append(reasons, types.Reason{
			ID:          "unresolved_dynamic_import",
			Description: fmt.Sprintf("Source file contains unresolved dynamic import: %s", name),
			Evidence:    fmt.Sprintf("%s in %s", name, strings.Join(files, ", ")),
		})
	}

	if hasPackageJSON {
		for name, files := range importedDeps {
			_, declared := declaredPackages[name]
			_, transitive := lockfileTransitiveDeps[name]
			if !declared && !transitive {
				reasons = append(reasons, types.Reason{
					ID:          "undeclared_source_import",
					Description: fmt.Sprintf("Source import %q is not declared in package.json", name),
					Evidence:    fmt.Sprintf("Imported in %s", strings.Join(files, ", ")),
				})
			}
		}

		for name, files := range importedDeps {
			_, declared := declaredPackages[name]
			_, transitive := lockfileTransitiveDeps[name]
			if !declared && transitive {
				reasons = append(reasons, types.Reason{
					ID:          "direct_use_of_transitive_dependency",
					Description: fmt.Sprintf("Source imports transitive dependency %q which is not directly declared in package.json", name),
					Evidence:    fmt.Sprintf("Imported in %s", strings.Join(files, ", ")),
				})
			}
		}

		for name := range declaredPackages {
			if _, imported := importedDeps[name]; !imported {
				reasons = append(reasons, types.Reason{
					ID:          "unused_declared_dependency",
					Description: fmt.Sprintf("Dependency %q declared in package.json is not used in any source files", name),
					Evidence:    name,
				})
			}
		}

		if hasLockfile {
			for name := range declaredPackages {
				if !lockfileDeps[name] {
					reasons = append(reasons, types.Reason{
						ID:          "package_json_lockfile_mismatch",
						Description: fmt.Sprintf("Dependency %q declared in package.json is missing from package-lock.json", name),
						Evidence:    name,
					})
				}
			}

			for name := range lockfileDirectDeps {
				if !declaredPackages[name] {
					reasons = append(reasons, types.Reason{
						ID:          "package_json_lockfile_mismatch",
						Description: fmt.Sprintf("Dependency %q is present in package-lock.json as a direct dependency but missing from package.json", name),
						Evidence:    name,
					})
				}
			}
		}
	}

	return reasons
}
