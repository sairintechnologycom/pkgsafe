package npm

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/git"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type ChangedDependency struct {
	Name        string `json:"package_name"`
	SourceFile  string `json:"source_file"`
	BaseVersion string `json:"base_version"`
	CurVersion  string `json:"current_version"`
	BaseType    string `json:"base_type"`
	CurType     string `json:"current_type"`
	BaseDirect  bool   `json:"base_direct"`
	CurDirect   bool   `json:"current_direct"`
}

type InventoryDiffReport struct {
	Added   []types.Dependency  `json:"added"`
	Removed []types.Dependency  `json:"removed"`
	Changed []ChangedDependency `json:"changed"`
}

// ScanInventoryGit gathers all dependencies from a specific Git revision (base branch).
func ScanInventoryGit(repoPath, revision string) ([]types.Dependency, error) {
	out, err := git.RunGit(repoPath, "ls-tree", "-r", "--name-only", revision)
	if err != nil {
		return nil, fmt.Errorf("git ls-tree: %w", err)
	}

	files := strings.Split(out, "\n")
	var packageJSONPaths []string
	var packageLockPaths []string
	var sourcePaths []string

	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		name := filepath.Base(file)
		if name == "node_modules" || strings.Contains(file, "/node_modules/") {
			continue
		}

		if name == "package.json" {
			packageJSONPaths = append(packageJSONPaths, file)
		} else if name == "package-lock.json" {
			packageLockPaths = append(packageLockPaths, file)
		} else if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".jsx") || strings.HasSuffix(name, ".tsx") {
			sourcePaths = append(sourcePaths, file)
		}
	}

	var results []types.Dependency
	directDepsMap := make(map[string]string)

	// 1. Process package.json files
	for _, relPath := range packageJSONPaths {
		bStr, err := git.RunGit(repoPath, "show", revision+":"+relPath)
		if err != nil {
			continue
		}
		b := []byte(bStr)
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
		bStr, err := git.RunGit(repoPath, "show", revision+":"+relPath)
		if err != nil {
			continue
		}
		b := []byte(bStr)
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
		bStr, err := git.RunGit(repoPath, "show", revision+":"+relPath)
		if err != nil {
			continue
		}
		content := stripComments(bStr)

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

// DiffInventories compares dependency lists.
func DiffInventories(baseDeps, currentDeps []types.Dependency) InventoryDiffReport {
	var report InventoryDiffReport

	baseMap := make(map[string]types.Dependency)
	for _, d := range baseDeps {
		if d.Name == "" {
			continue
		}
		key := fmt.Sprintf("%s:%s", d.SourceFile, d.Name)
		baseMap[key] = d
	}

	currentMap := make(map[string]types.Dependency)
	for _, d := range currentDeps {
		if d.Name == "" {
			continue
		}
		key := fmt.Sprintf("%s:%s", d.SourceFile, d.Name)
		currentMap[key] = d
	}

	for key, cur := range currentMap {
		if base, ok := baseMap[key]; ok {
			if base.VersionRange != cur.VersionRange || base.DependencyType != cur.DependencyType || base.Direct != cur.Direct {
				report.Changed = append(report.Changed, ChangedDependency{
					Name:        cur.Name,
					SourceFile:  cur.SourceFile,
					BaseVersion: base.VersionRange,
					CurVersion:  cur.VersionRange,
					BaseType:    base.DependencyType,
					CurType:     cur.DependencyType,
					BaseDirect:  base.Direct,
					CurDirect:   cur.Direct,
				})
			}
		} else {
			report.Added = append(report.Added, cur)
		}
	}

	for key, base := range baseMap {
		if _, ok := currentMap[key]; !ok {
			report.Removed = append(report.Removed, base)
		}
	}

	return report
}
