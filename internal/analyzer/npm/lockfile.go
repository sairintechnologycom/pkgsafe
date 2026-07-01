package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/intel"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
	"github.com/sairintechnologycom/pkgsafe/internal/typosquat"
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
	deps := make(map[string]string)

	for path, pkg := range lf.Packages {
		if path == "" || path == "node_modules" {
			continue
		}
		name := extractModuleName(path)
		if name != "" {
			names = append(names, name)
			if pkg.Version != "" {
				deps[name] = pkg.Version
			}
		}
	}
	for name, dep := range lf.Dependencies {
		names = append(names, name)
		if dep.Version != "" {
			deps[name] = dep.Version
		}
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
		if policy.IsBlocked(pol, "npm", name) {
			reasons = append(reasons, types.Reason{
				ID:          "blocked_package",
				Description: fmt.Sprintf("Lockfile contains blocked dependency %q", name),
				Evidence:    name,
			})
		}
		matches := typosquat.Check(name)
		if len(matches) > 0 {
			alts = append(alts, matches...)
			reasons = append(reasons, types.Reason{ID: "typosquat_candidate", Description: "Lockfile contains dependency resembling a popular package", Evidence: name})
			reasons = append(reasons, types.Reason{ID: "missing_repository", Description: "Lockfile dependency metadata does not include a source repository", Evidence: name})
		}
	}

	// Fetch vulnerabilities from local DB for each dependency
	d, err := db.Open("")
	var resultVulns []types.Vulnerability
	if err == nil {
		defer d.Close()
		ctx := context.Background()
		for name, ver := range deps {
			vulns, err := d.GetVulnerabilitiesForPackage(ctx, "npm", name)
			if err != nil {
				continue
			}
			for _, v := range vulns {
				if intel.IsVersionAffected(ver, v) {
					resultVulns = append(resultVulns, typeVuln(v))

					if intel.IsMalware(v) {
						reasons = append(reasons, types.Reason{
							ID:          "known_malware_indicator",
							Description: fmt.Sprintf("Lockfile contains dependency %q with malware", name),
							Evidence:    name + "@" + ver,
						})
					} else {
						reasons = append(reasons, types.Reason{
							ID:          "known_vulnerability_" + v.Severity,
							Description: fmt.Sprintf("Lockfile contains dependency %q with a %s severity advisory", name, v.Severity),
							Evidence:    name + "@" + ver,
						})
					}
				}
			}
		}
	}

	evalRes := risk.Evaluate(pkg, reasons, nil, nil, unique(alts), pol)
	evalRes.Vulnerabilities = dedupeVulnerabilities(resultVulns)
	return evalRes, nil
}

func typeVuln(v db.Vulnerability) types.Vulnerability {
	return types.Vulnerability{
		ID:            v.ID,
		Source:        v.Source,
		Ecosystem:     v.Ecosystem,
		PackageName:   v.PackageName,
		Version:       v.Version,
		Aliases:       v.Aliases,
		Severity:      v.Severity,
		Summary:       v.Summary,
		Details:       v.Details,
		FixedVersions: v.FixedVersions,
		References:    v.References,
		PublishedAt:   formatVulnTime(v.PublishedAt),
		ModifiedAt:    formatVulnTime(v.ModifiedAt),
		FetchedAt:     formatVulnTime(v.FetchedAt),
	}
}

func formatVulnTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
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

func dedupeVulnerabilities(in []types.Vulnerability) []types.Vulnerability {
	seen := make(map[string]bool)
	var out []types.Vulnerability
	for _, v := range in {
		if !seen[v.ID] {
			seen[v.ID] = true
			out = append(out, v)
		}
	}
	return out
}
