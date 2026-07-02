package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/audit"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/report"
)

// GenerateGovernanceReportParams defines input for generate_governance_report.
type GenerateGovernanceReportParams struct {
	RepoPath        string `json:"repo_path"`
	Format          string `json:"format"`
	IncludeAuditLog bool   `json:"include_audit_log"`
}

type GenerateGovernanceReportResult struct {
	ReportGenerated bool           `json:"report_generated"`
	ReportType      string         `json:"report_type"`
	Files           []string       `json:"files"`
	Summary         map[string]int `json:"summary"`
}

// GenerateGovernanceReport generates risk reports via the MCP interface.
func (e *Executor) GenerateGovernanceReport(args json.RawMessage) CallToolResult {
	var p GenerateGovernanceReportParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.RepoPath == "" {
		p.RepoPath = "."
	}
	if p.Format == "" {
		p.Format = "json"
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

	r, err := report.GenerateReport(p.RepoPath, pol, true)
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("REPORT_GENERATION_FAILURE", "Failed to generate report: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	// AI agents should not access raw audit logs / overrides unless include_audit_log is enabled
	if !p.IncludeAuditLog {
		r.Overrides = nil
		r.Summary.DeveloperOverrides = 0
	}

	var files []string
	baseOutput := filepath.Join(p.RepoPath, "pkgsafe-report")

	writeFmt := func(fType string) error {
		switch fType {
		case "markdown":
			content, _ := report.ExportMarkdown(r)
			path := baseOutput + ".md"
			files = append(files, filepath.Base(path))
			return os.WriteFile(path, []byte(content), 0644)
		case "html":
			content, _ := report.ExportHTML(r)
			path := baseOutput + ".html"
			files = append(files, filepath.Base(path))
			return os.WriteFile(path, []byte(content), 0644)
		default: // json
			content, _ := report.ExportJSON(r)
			path := baseOutput + ".json"
			files = append(files, filepath.Base(path))
			return os.WriteFile(path, []byte(content), 0644)
		}
	}

	if p.Format == "all" {
		for _, f := range []string{"markdown", "json", "html"} {
			_ = writeFmt(f)
		}
	} else {
		_ = writeFmt(p.Format)
	}

	res := GenerateGovernanceReportResult{
		ReportGenerated: true,
		ReportType:      "repository-risk-report",
		Files:           files,
		Summary: map[string]int{
			"packages_scanned": r.Summary.PackagesScanned,
			"blocked":          r.Summary.Blocked,
			"warned":           r.Summary.Warnings,
		},
	}

	b, _ := json.MarshalIndent(res, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(b),
		}},
		IsError: false,
	}
}

// GetRecentPackageDecisionsParams defines input for get_recent_package_decisions.
type GetRecentPackageDecisionsParams struct {
	Limit     int    `json:"limit"`
	Ecosystem string `json:"ecosystem"`
}

type DecisionItem struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Decision  string `json:"decision"`
	RiskScore int    `json:"risk_score"`
	Ecosystem string `json:"ecosystem"`
}

// GetRecentPackageDecisions returns recent validation actions.
func (e *Executor) GetRecentPackageDecisions(args json.RawMessage) CallToolResult {
	var p GetRecentPackageDecisionsParams
	_ = json.Unmarshal(args, &p)

	if p.Limit <= 0 {
		p.Limit = 10
	}

	entries, err := audit.ReadAuditLog("")
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("AUDIT_READ_FAILURE", "Failed to read audit log: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	var decisions []DecisionItem
	count := 0
	for i := len(entries) - 1; i >= 0 && count < p.Limit; i-- {
		entry := entries[i]
		if p.Ecosystem != "" && !strings.EqualFold(entry.Ecosystem, p.Ecosystem) {
			continue
		}
		for _, pkg := range entry.Packages {
			decisions = append(decisions, DecisionItem{
				Package:   pkg.Name,
				Version:   pkg.Version,
				Decision:  pkg.Decision,
				RiskScore: pkg.RiskScore,
				Ecosystem: entry.Ecosystem,
			})
			count++
			if count >= p.Limit {
				break
			}
		}
	}

	b, _ := json.MarshalIndent(decisions, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(b),
		}},
		IsError: false,
	}
}

// GetPolicyEvidenceParams defines input for get_policy_evidence.
type GetPolicyEvidenceParams struct{}

// GetPolicyEvidence returns details of the active policy configuration.
func (e *Executor) GetPolicyEvidence(args json.RawMessage) CallToolResult {
	var p GetPolicyEvidenceParams
	_ = json.Unmarshal(args, &p)

	pol, err := policy.ResolvePolicy("", "", e.PolicyPath, e.Mode, "")
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_RESOLVE_FAILURE", "Failed to resolve policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	evidence := map[string]any{
		"policy_source":  nonEmpty(pol.PolicyPackSource, "local"),
		"policy_name":    nonEmpty(pol.PolicyPackName, "default-policy"),
		"policy_version": nonEmpty(pol.PolicyPackVersion, "1"),
		"policy_owner":   nonEmpty(pol.PolicyPackOwner, "local"),
		"overall_mode":   pol.Mode,
		"thresholds":     pol.Thresholds,
		"controls": map[string]bool{
			"block_known_malware_always":     pol.InstallInterception.BlockKnownMalwareAlways,
			"block_credential_access_always": pol.InstallInterception.BlockCredentialAccessAlways,
			"allow_force_risk_accept":        pol.InstallInterception.AllowForceRiskAccept,
		},
	}

	b, _ := json.MarshalIndent(evidence, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(b),
		}},
		IsError: false,
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
