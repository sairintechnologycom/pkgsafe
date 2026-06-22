package ci

import (
	"encoding/json"
	"strings"
)

type packageLock struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	LockfileVersion int    `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
		Dev       bool   `json:"dev"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

type Dependency struct {
	Name    string
	Version string
}

type ChangedPackage struct {
	Name        string
	FromVersion string
	ToVersion   string
}

func parseLockfileDeps(content []byte) (map[string]map[string]bool, error) {
	var lf packageLock
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, err
	}
	deps := make(map[string]map[string]bool)
	addDep := func(name, ver string) {
		if name == "" || ver == "" {
			return
		}
		if _, ok := deps[name]; !ok {
			deps[name] = make(map[string]bool)
		}
		deps[name][ver] = true
	}

	for path, pkg := range lf.Packages {
		if path == "" || path == "node_modules" {
			continue
		}
		name := extractModuleName(path)
		if name != "" && pkg.Version != "" {
			addDep(name, pkg.Version)
		}
	}
	for name, dep := range lf.Dependencies {
		if name != "" && dep.Version != "" {
			addDep(name, dep.Version)
		}
	}
	return deps, nil
}

func DiffLockfilesDetailed(currentContent, baselineContent []byte) ([]Dependency, []ChangedPackage, error) {
	currentDeps, err := parseLockfileDeps(currentContent)
	if err != nil {
		return nil, nil, err
	}
	baselineDeps, err := parseLockfileDeps(baselineContent)
	if err != nil {
		return nil, nil, err
	}

	var deps []Dependency
	var details []ChangedPackage

	for name, currentVersions := range currentDeps {
		baselineVersions, exists := baselineDeps[name]
		if !exists {
			for ver := range currentVersions {
				deps = append(deps, Dependency{Name: name, Version: ver})
				details = append(details, ChangedPackage{
					Name:        name,
					FromVersion: "added",
					ToVersion:   ver,
				})
			}
		} else {
			for ver := range currentVersions {
				if !baselineVersions[ver] {
					deps = append(deps, Dependency{Name: name, Version: ver})
					var fromVers []string
					for bv := range baselineVersions {
						fromVers = append(fromVers, bv)
					}
					fromStr := strings.Join(fromVers, ", ")
					details = append(details, ChangedPackage{
						Name:        name,
						FromVersion: fromStr,
						ToVersion:   ver,
					})
				}
			}
		}
	}
	return deps, details, nil
}

func extractModuleName(path string) string {
	const prefix = "node_modules/"
	idx := lastIndex(path, prefix)
	if idx < 0 {
		return ""
	}
	name := path[idx+len(prefix):]
	if len(name) == 0 {
		return ""
	}
	if name[0] == '@' {
		parts := splitN(name, '/', 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return name
	}
	parts := splitN(name, '/', 2)
	return parts[0]
}

func lastIndex(s, sep string) int {
	last := -1
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			last = i
		}
	}
	return last
}

func splitN(s string, sep byte, n int) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		out = append(out, s[start:])
	}
	return out
}
