package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

type JSONResult struct {
	Ecosystem        string                `json:"ecosystem"`
	Package          string                `json:"package"`
	Version          string                `json:"version"`
	Mode             string                `json:"mode"`
	Decision         types.Decision        `json:"decision"`
	RiskScore        int                   `json:"risk_score"`
	Thresholds       types.Thresholds      `json:"thresholds"`
	Reasons          []types.Reason        `json:"reasons"`
	Recommended      string                `json:"recommended_action"`
	Enforcement      string                `json:"enforcement,omitempty"`
	PackageIdentity  types.PackageIdentity `json:"package_identity,omitempty"`
	LifecycleScripts []string              `json:"lifecycle_scripts,omitempty"`
	Suspicious       []string              `json:"suspicious_patterns,omitempty"`
}

func Write(w io.Writer, result types.ScanResult, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(JSONResult{
			Ecosystem:        result.Package.Ecosystem,
			Package:          result.Package.Name,
			Version:          emptyLatest(result.Package.Version),
			Mode:             result.Mode,
			Decision:         result.Decision,
			RiskScore:        result.Score,
			Thresholds:       result.Thresholds,
			Reasons:          result.Reasons,
			Recommended:      recommendedAction(result),
			Enforcement:      result.Enforcement,
			PackageIdentity:  result.Package,
			LifecycleScripts: result.Lifecycle,
			Suspicious:       result.Suspicious,
		})
	}

	fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(string(result.Decision)))
	if result.Mode != "" {
		fmt.Fprintf(w, "Mode: %s\n", strings.ToUpper(result.Mode))
	}
	if result.Enforcement != "" {
		fmt.Fprintf(w, "Enforcement: %s\n", result.Enforcement)
	}
	fmt.Fprintf(w, "Package: %s/%s@%s\n", result.Package.Ecosystem, result.Package.Name, emptyLatest(result.Package.Version))
	fmt.Fprintf(w, "Risk Score: %d/100\n", result.Score)
	if len(result.Lifecycle) > 0 {
		fmt.Fprintf(w, "Lifecycle Scripts: %s\n", strings.Join(result.Lifecycle, ", "))
	}
	if len(result.Reasons) > 0 {
		fmt.Fprintln(w, "\nReasons:")
		for _, r := range result.Reasons {
			fmt.Fprintf(w, "- [%s %+d] %s: %s", r.Severity, r.ScoreImpact, r.ID, r.Description)
			if r.Evidence != "" {
				fmt.Fprintf(w, " (%s)", r.Evidence)
			}
			fmt.Fprintln(w)
		}
	}
	if len(result.SafeAlternates) > 0 {
		fmt.Fprintf(w, "\nPossible safe alternatives: %s\n", strings.Join(result.SafeAlternates, ", "))
	}
	fmt.Fprintf(w, "\nRecommended Action:\n%s\n", recommendedAction(result))
	return nil
}

func emptyLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

func recommendedAction(result types.ScanResult) string {
	if result.Recommended != "" {
		return result.Recommended
	}
	switch result.Decision {
	case types.DecisionBlock:
		return "Do not install this package."
	case types.DecisionWarn:
		return "Review package before installing."
	default:
		return "Package appears safe to install based on current checks."
	}
}
