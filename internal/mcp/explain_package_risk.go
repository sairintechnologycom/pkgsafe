package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/sairintechnologycom/pkgsafe/internal/output"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ExplainPackageRiskParams defines the input arguments for explaining package risks.
type ExplainPackageRiskParams struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Offline   bool   `json:"offline"`
}

// ExplainPackageRiskResult defines the output schema for explaining package risk.
type ExplainPackageRiskResult struct {
	Ecosystem         string                `json:"ecosystem"`
	Package           string                `json:"package"`
	Version           string                `json:"version"`
	Summary           string                `json:"summary"`
	Decision          string                `json:"decision"`
	RiskScore         int                   `json:"risk_score"`
	Metadata          ExplainMetadata       `json:"metadata"`
	TopRisks          []string              `json:"top_risks"`
	Vulnerabilities   []types.Vulnerability `json:"vulnerabilities"`
	RecommendedAction string                `json:"recommended_action"`
}

type ExplainMetadata struct {
	RepositoryPresent bool     `json:"repository_present"`
	LicensePresent    bool     `json:"license_present"`
	LifecycleScripts  []string `json:"lifecycle_scripts"`
	LatestVersion     string   `json:"latest_version"`
}

// ExplainPackageRisk provides detailed safety risk explanations.
func (e *Executor) ExplainPackageRisk(args json.RawMessage) CallToolResult {
	var p ExplainPackageRiskParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.Ecosystem == "" {
		p.Ecosystem = "npm"
	}
	if p.Ecosystem != "npm" && p.Ecosystem != "pypi" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("UNSUPPORTED_ECOSYSTEM", "Supported ecosystems are npm and pypi", map[string]string{"ecosystem": p.Ecosystem}),
			}},
			IsError: true,
		}
	}

	if p.Name == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("MISSING_PACKAGE_NAME", "Package name is required", nil),
			}},
			IsError: true,
		}
	}

	if p.Version == "" {
		p.Version = "latest"
	}

	pol, err := policy.Load(e.PolicyPath)
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if e.Mode != "" {
		pol.Mode = policy.ParseMode(e.Mode)
	}

	var res types.ScanResult
	var scanErr error
	if p.Ecosystem == "pypi" {
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	} else {
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	}
	if scanErr != nil {
		te := MapScanError(scanErr, p.Ecosystem, p.Name, p.Version)
		b, _ := json.MarshalIndent(te, "", "  ")
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: string(b),
			}},
			IsError: true,
		}
	}

	hasRepo := true
	hasLicense := true
	var topRisks []string
	for _, r := range res.Reasons {
		if r.ID == "missing_repository" {
			hasRepo = false
		}
		if r.ID == "missing_license" {
			hasLicense = false
		}
		if r.ScoreImpact > 0 {
			topRisks = append(topRisks, r.Description)
		}
	}

	summary := "Package has low risk."
	if res.Decision == types.DecisionBlock {
		summary = "Package is blocked due to critical risk findings."
	} else if res.Decision == types.DecisionWarn {
		summary = fmt.Sprintf("Package has moderate risk (score: %d) and requires review.", res.Score)
		if len(res.Lifecycle) > 0 {
			summary = "Package has moderate risk due to lifecycle scripts."
		}
	}

	toolRes := ExplainPackageRiskResult{
		Ecosystem: res.Package.Ecosystem,
		Package:   res.Package.Name,
		Version:   res.Package.Version,
		Summary:   summary,
		Decision:  string(res.Decision),
		RiskScore: res.Score,
		Metadata: ExplainMetadata{
			RepositoryPresent: hasRepo,
			LicensePresent:    hasLicense,
			LifecycleScripts:  res.Lifecycle,
			LatestVersion:     res.Package.Version,
		},
		TopRisks:          topRisks,
		Vulnerabilities:   res.Vulnerabilities,
		RecommendedAction: output.RecommendedAction(res),
	}

	b, _ := json.MarshalIndent(toolRes, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(b),
		}},
		IsError: false,
	}
}
