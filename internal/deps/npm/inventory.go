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
	// Matches: import("pkg"), require("pkg")
	callImportRegex = regexp.MustCompile(`\b(?:import|require)\(\s*['"]([^'"]+)['"]\s*\)`)

	nodeBuiltins = map[string]bool{
		"assert":           true,
		"async_hooks":      true,
		"buffer":           true,
		"child_process":    true,
		"cluster":          true,
		"console":          true,
		"constants":        true,
		"crypto":           true,
		"dgram":            true,
		"dns":              true,
		"domain":           true,
		"events":           true,
		"fs":               true,
		"http":             true,
		"http2":            true,
		"https":            true,
		"inspector":        true,
		"module":           true,
		"net":              true,
		"os":               true,
		"path":             true,
		"perf_hooks":       true,
		"process":          true,
		"punycode":         true,
		"querystring":      true,
		"readline":         true,
		"repl":             true,
		"stream":           true,
		"string_decoder":   true,
		"sys":              true,
		"timers":           true,
		"tls":              true,
		"trace_events":     true,
		"tty":              true,
		"url":              true,
		"util":             true,
		"v8":               true,
		"vm":               true,
		"wasi":             true,
		"worker_threads":   true,
		"zlib":             true,
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
	Name            string                            `json:"name"`
	Version         string                            `json:"version"`
	LockfileVersion int                               `json:"lockfileVersion"`
	Packages        map[string]packageLockPackage     `json:"packages"`
	Dependencies    map[string]packageLockDependency `json:"dependencies"`
}

type packageLockPackage struct {
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type packageLockDependency struct {
	Version      string                           `json:"version"`
	Dev          bool                             `json:"dev"`
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
			// Skip or return error? Robustness requires handling malformed files gracefully.
			// The task states "malformed package.json" is a robustness test, so let's continue
			// or record it as empty, but not fail the entire command.
			continue
		}

		// Helper to extract bundled dependencies as list of names
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
				// Track direct dependency types globally (precedence: production > dev > peer > optional)
				if current, ok := directDepsMap[name]; !ok || precedence(actualType) > precedence(current) {
					directDepsMap[name] = actualType
				}
			}
		}

		addDeps(pj.Dependencies, "production")
		addDeps(pj.DevDependencies, "dev")
		addDeps(pj.PeerDependencies, "peer")
		addDeps(pj.OptionalDependencies, "optional")
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
			continue // Skip malformed lockfiles gracefully
		}

		if len(lf.Packages) > 0 {
			// Lockfile v2 or v3
			// First, identify all workspace packages. They are keys in Packages that are not empty and don't start with "node_modules/"
			// Also, compile the direct dependencies declared by the root package and all workspace packages
			lockDirectDeps := make(map[string]string)
			for path, pkg := range lf.Packages {
				if path == "" || !strings.HasPrefix(path, "node_modules/") {
					// Root or workspace package
					collectDirectDeps(pkg.Dependencies, "production", lockDirectDeps)
					collectDirectDeps(pkg.DevDependencies, "dev", lockDirectDeps)
					collectDirectDeps(pkg.PeerDependencies, "peer", lockDirectDeps)
					collectDirectDeps(pkg.OptionalDependencies, "optional", lockDirectDeps)
				}
			}

			// Now extract all package entries
			for path, pkg := range lf.Packages {
				if path == "" || !strings.HasPrefix(path, "node_modules/") {
					continue // Skip local root or workspace packages
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
					// Fallback to global package.json direct dependencies map
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
					Resolved:       pkg.Resolved,
					Integrity:      pkg.Integrity,
					PackagePath:    path,
				})
			}
		} else if len(lf.Dependencies) > 0 {
			// Lockfile v1 fallback
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

		// Run import/require regexes
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
		findMatches(callImportRegex)

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
			PackagePath:    pkgPath,
		}
		*out = append(*out, d)

		if len(dep.Dependencies) > 0 {
			parseLockfileV1Deps(dep.Dependencies, pkgPath, directMap, sourceFile, out)
		}
	}
}

func stripComments(content string) string {
	// Strip single line comments
	singleLine := regexp.MustCompile(`//.*`)
	content = singleLine.ReplaceAllString(content, "")

	// Strip multi-line comments
	multiLine := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	content = multiLine.ReplaceAllString(content, "")

	return content
}

func parseImportPackage(importPath string) (string, bool) {
	importPath = strings.TrimSpace(importPath)
	if importPath == "" {
		return "", false
	}
	// Ignore relative and absolute paths
	if strings.HasPrefix(importPath, ".") || strings.HasPrefix(importPath, "/") || filepath.IsAbs(importPath) {
		return "", false
	}
	// Ignore node builtins
	if nodeBuiltins[importPath] || strings.HasPrefix(importPath, "node:") {
		return "", false
	}
	// Check if it's a scoped package, e.g. @scope/pkg or @scope/pkg/path
	if strings.HasPrefix(importPath, "@") {
		parts := strings.Split(importPath, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1], true
		}
		return importPath, true
	}
	// Standard package, e.g. pkg or pkg/path
	parts := strings.Split(importPath, "/")
	return parts[0], true
}
