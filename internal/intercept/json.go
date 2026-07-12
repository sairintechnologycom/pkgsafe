package intercept

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type JSONOutput struct {
	SchemaVersion     string            `json:"schema_version"`
	Command           string            `json:"command"`
	Ecosystem         string            `json:"ecosystem"`
	PackageManager    string            `json:"package_manager"`
	Mode              string            `json:"mode"`
	Decision          string            `json:"decision"`
	InstallExecuted   bool              `json:"install_executed"`
	DryRun            bool              `json:"dry_run"`
	Packages          []JSONPackageInfo `json:"packages"`
	RecommendedAction string            `json:"recommended_action"`
}

type JSONPackageInfo struct {
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Decision  string         `json:"decision"`
	RiskScore int            `json:"risk_score"`
	Reasons   []types.Reason `json:"reasons"`
}

func PrintJSONOutput(w io.Writer, cmd *InstallCommand, results []types.ScanResult, overallDecision types.Decision, sf SafetyFlags, executed bool) error {
	packages := make([]JSONPackageInfo, len(results))
	for i, res := range results {
		packages[i] = JSONPackageInfo{
			Name:      res.Package.Name,
			Version:   res.Package.Version,
			Decision:  string(res.Decision),
			RiskScore: res.Score,
			Reasons:   res.Reasons,
		}
	}

	recommended := "Proceed with installation."
	if overallDecision == types.DecisionBlock {
		recommended = "Do not install blocked packages."
	} else if overallDecision == types.DecisionReviewRequired {
		recommended = "Request authorized human review before installing."
	} else if overallDecision == types.DecisionWarn {
		recommended = "Inspect package details and proceed with caution."
	}

	out := JSONOutput{
		SchemaVersion:     "1.0",
		Command:           strings.Join(RedactCommand(cmd.RawCommand), " "),
		Ecosystem:         cmd.Ecosystem,
		PackageManager:    cmd.PackageManager,
		Mode:              sf.Mode,
		Decision:          string(overallDecision),
		InstallExecuted:   executed,
		DryRun:            sf.DryRun,
		Packages:          packages,
		RecommendedAction: recommended,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
