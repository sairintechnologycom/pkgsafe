package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/types"
	"github.com/niyam-ai/pkgsafe/internal/typosquat"
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

func AnalyzeLockfile(path string, pol policy.Policy) (types.ScanResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return types.ScanResult{}, err
	}
	var lf packageLock
	if err := json.Unmarshal(b, &lf); err != nil {
		return types.ScanResult{}, fmt.Errorf("parse lockfile: %w", err)
	}

	pkg := types.PackageIdentity{Ecosystem: "npm-lock", Name: lf.Name, Version: lf.Version}
	var reasons []types.Reason
	var alts []string

	var names []string
	for path := range lf.Packages {
		if path == "" || path == "node_modules" {
			continue
		}
		name := extractModuleName(path)
		if name != "" {
			names = append(names, name)
		}
	}
	for name := range lf.Dependencies {
		names = append(names, name)
	}
	names = unique(names)
	sort.Strings(names)

	if len(names) == 0 {
		reasons = append(reasons, types.Reason{ID: "empty_lockfile", Description: "No dependencies found in lockfile"})
	}
	if len(names) > 500 {
		reasons = append(reasons, types.Reason{ID: "large_dependency_graph", Description: "Large dependency graph increases transitive supply-chain exposure", Evidence: fmt.Sprintf("%d packages", len(names))})
	}
	for _, name := range names {
		matches := typosquat.Check(name)
		if len(matches) > 0 {
			alts = append(alts, matches...)
			reasons = append(reasons, types.Reason{ID: "typosquat_candidate", Description: "Lockfile contains dependency resembling a popular package", Evidence: name})
			reasons = append(reasons, types.Reason{ID: "missing_repository", Description: "Lockfile dependency metadata does not include a source repository", Evidence: name})
		}
	}
	return risk.Evaluate(pkg, reasons, nil, nil, unique(alts), pol), nil
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
	out = append(out, s[start:])
	return out
}
