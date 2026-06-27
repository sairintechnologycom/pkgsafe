package npm

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

// namedFile is a file path paired with its already-read contents. Callers read
// files however they like (filesystem walk, git tree) and hand the contents to
// buildNPMInventory, which owns all parsing/aggregation logic.
type namedFile struct {
	relPath string
	content []byte
}

// buildNPMInventory parses pre-read package.json, package-lock.json, and source
// files into a dependency inventory. It is the single source of truth shared by
// ScanInventory (filesystem) and ScanInventoryGit (git tree); only file
// discovery/reading differs between those callers.
func buildNPMInventory(packageJSON, lockFiles, source []namedFile) []types.Dependency {
	var results []types.Dependency
	directDepsMap := make(map[string]string) // package_name -> dependency_type

	// 1. Process package.json files
	for _, f := range packageJSON {
		var pj PackageJSON
		if err := json.Unmarshal(f.content, &pj); err != nil {
			continue
		}

		bundledNames := append(parseBundled(pj.BundledDependencies), parseBundled(pj.BundleDependencies)...)
		bundledSet := make(map[string]bool)
		for _, name := range bundledNames {
			bundledSet[name] = true
		}
		declaredSet := make(map[string]bool)

		addDeps := func(deps map[string]string, depType string) {
			for name, versionRange := range deps {
				declaredSet[name] = true
				actualType := depType
				if bundledSet[name] {
					actualType = "bundled"
				}
				results = append(results, types.Dependency{
					Ecosystem:      "npm",
					Name:           name,
					VersionRange:   versionRange,
					SourceFile:     f.relPath,
					DependencyType: actualType,
					Direct:         true,
					Dev:            actualType == "dev",
					Optional:       actualType == "optional",
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
		for _, name := range bundledNames {
			if declaredSet[name] {
				continue
			}
			results = append(results, types.Dependency{
				Ecosystem:      "npm",
				Name:           name,
				VersionRange:   "",
				SourceFile:     f.relPath,
				DependencyType: "bundled",
				Direct:         true,
			})
			directDepsMap[name] = "bundled"
		}

		// Emit a pseudo-dependency to track presence of package.json
		results = append(results, types.Dependency{
			Ecosystem:      "npm",
			Name:           "",
			VersionRange:   "",
			SourceFile:     f.relPath,
			DependencyType: "package.json",
			Direct:         true,
		})
	}

	// 2. Process package-lock.json files
	for _, f := range lockFiles {
		var lf packageLock
		if err := json.Unmarshal(f.content, &lf); err != nil {
			continue
		}

		// Emit a pseudo-dependency to track presence of package-lock.json
		results = append(results, types.Dependency{
			Ecosystem:      "npm",
			Name:           "",
			VersionRange:   "",
			SourceFile:     f.relPath,
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
					SourceFile:     f.relPath,
					DependencyType: depType,
					Direct:         direct,
					Dev:            pkg.Dev || depType == "dev",
					Optional:       pkg.Optional || depType == "optional",
					Resolved:       pkg.Resolved,
					Integrity:      pkg.Integrity,
					PackagePath:    path,
				})
			}
		} else if len(lf.Dependencies) > 0 {
			var v1Out []types.Dependency
			parseLockfileV1Deps(lf.Dependencies, "", directDepsMap, f.relPath, &v1Out)
			results = append(results, v1Out...)
		}
	}

	// 3. Process source import scanning
	for _, f := range source {
		content := stripComments(string(f.content))

		importedPkgs := make(map[string]bool)

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

		args := extractCallArguments(content)
		for _, arg := range args {
			if isQuoted(arg) {
				cleanPkg := arg[1 : len(arg)-1]
				if pkg, ok := parseImportPackage(cleanPkg); ok {
					importedPkgs[pkg] = true
				}
			} else {
				results = append(results, types.Dependency{
					Ecosystem:      "npm",
					Name:           arg,
					VersionRange:   "",
					SourceFile:     f.relPath,
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
				SourceFile:     f.relPath,
				DependencyType: "source-import",
				Direct:         true,
			})
		}
	}

	return results
}
