package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/types"
	"github.com/niyam-ai/pkgsafe/internal/typosquat"
)

type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	Repository      any               `json:"repository"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func AnalyzePackageDir(dir string, pol policy.Policy) (types.ScanResult, error) {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("read package.json: %w", err)
	}
	return AnalyzePackageJSON(b, pol)
}

func AnalyzePackageJSON(b []byte, pol policy.Policy) (types.ScanResult, error) {
	var pj PackageJSON
	if err := json.Unmarshal(b, &pj); err != nil {
		return types.ScanResult{}, fmt.Errorf("parse package.json: %w", err)
	}
	if pj.Name == "" {
		pj.Name = "unknown"
	}

	pkg := types.PackageIdentity{Ecosystem: "npm", Name: pj.Name, Version: pj.Version}
	var reasons []types.Reason
	var lifecycle []string
	var suspicious []string

	for _, name := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if script, ok := pj.Scripts[name]; ok {
			lifecycle = append(lifecycle, name)
			reasons = append(reasons, types.Reason{
				ID: "lifecycle_script_present", Severity: "medium",
				Description: "Package defines an install lifecycle script",
				Evidence:    name + "=" + script, ScoreImpact: 20,
			})
			lower := strings.ToLower(script)
			for _, pat := range pol.BlockPatterns {
				if containsFold(lower, pat) {
					suspicious = append(suspicious, pat)
					reasons = append(reasons, types.Reason{
						ID: "credential_or_secret_access", Severity: "critical",
						Description: "Lifecycle script references credential or secret material",
						Evidence:    pat, ScoreImpact: 80,
					})
				}
			}
			for _, pat := range pol.WarnPatterns {
				if containsFold(lower, pat) {
					suspicious = append(suspicious, pat)
					reasons = append(reasons, types.Reason{
						ID: "suspicious_lifecycle_pattern", Severity: "high",
						Description: "Lifecycle script contains suspicious command or network pattern",
						Evidence:    pat, ScoreImpact: 25,
					})
				}
			}
		}
	}
	if len(lifecycle) == 0 {
		reasons = append(reasons, types.Reason{
			ID: "no_lifecycle_scripts", Severity: "info",
			Description: "No install lifecycle scripts detected",
			ScoreImpact: 0,
		})
	}

	alts := typosquat.Check(pj.Name)
	if len(alts) > 0 {
		reasons = append(reasons, types.Reason{
			ID: "possible_typosquat", Severity: "high",
			Description: "Package name resembles a popular package",
			Evidence:    strings.Join(alts, ", "), ScoreImpact: 35,
		})
	}

	if pj.Repository == nil || fmt.Sprint(pj.Repository) == "" {
		reasons = append(reasons, types.Reason{
			ID: "missing_repository", Severity: "low",
			Description: "Package metadata does not include a source repository",
			ScoreImpact: 10,
		})
	} else {
		reasons = append(reasons, types.Reason{
			ID: "repository_metadata_present", Severity: "info",
			Description: "Package metadata includes a source repository",
			ScoreImpact: 0,
		})
	}

	return risk.Evaluate(pkg, dedupeReasons(reasons), unique(lifecycle), unique(suspicious), alts), nil
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func dedupeReasons(in []types.Reason) []types.Reason {
	seen := map[string]bool{}
	out := []types.Reason{}
	for _, r := range in {
		key := r.ID + ":" + r.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}
