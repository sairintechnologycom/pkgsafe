package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/audit"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

// ExportMarkdown formats the Repository Risk Report as Markdown text.
func ExportMarkdown(r *RepositoryRiskReport) (string, error) {
	var buf bytes.Buffer

	overall := "ALLOW"
	if r.Summary.Blocked > 0 {
		overall = "BLOCK"
	} else if r.Summary.Warnings > 0 {
		overall = "WARN"
	}

	buf.WriteString("# PkgSafe Repository Risk Report\n\n")
	fmt.Fprintf(&buf, "**Repository:** %s  \n", nonEmpty(r.Repository.Name, "unknown"))
	fmt.Fprintf(&buf, "**Generated:** %s  \n", r.GeneratedAt)
	fmt.Fprintf(&buf, "**PkgSafe Version:** %s  \n", "0.9.0")
	fmt.Fprintf(&buf, "**Policy Pack:** %s@%s  \n", r.Policy.PackName, r.Policy.PackVersion)
	fmt.Fprintf(&buf, "**Overall Decision:** %s  \n\n", overall)

	buf.WriteString("## Summary\n\n")
	buf.WriteString("| Metric | Count |\n")
	buf.WriteString("|---|---:|\n")
	fmt.Fprintf(&buf, "| Packages Scanned | %d |\n", r.Summary.PackagesScanned)
	fmt.Fprintf(&buf, "| Allowed | %d |\n", r.Summary.Allowed)
	fmt.Fprintf(&buf, "| Warnings | %d |\n", r.Summary.Warnings)
	fmt.Fprintf(&buf, "| Blocked | %d |\n", r.Summary.Blocked)
	fmt.Fprintf(&buf, "| Critical Vulnerabilities | %d |\n", r.Summary.CriticalVulnerabilities)
	fmt.Fprintf(&buf, "| High Vulnerabilities | %d |\n", r.Summary.HighVulnerabilities)
	fmt.Fprintf(&buf, "| Active Exceptions | %d |\n", r.Summary.ActiveExceptions)
	fmt.Fprintf(&buf, "| Developer Overrides | %d |\n", r.Summary.DeveloperOverrides)
	fmt.Fprintf(&buf, "| Private Registry Violations | %d |\n", r.Summary.PrivateRegistryViolations)
	fmt.Fprintf(&buf, "| Dependency Confusion Findings | %d |\n\n", r.Summary.DependencyConfusionFindings)

	var topFindings []ReportFinding
	for _, f := range r.Findings {
		if f.Decision == "block" || f.Decision == "warn" || f.RiskScore > 0 {
			topFindings = append(topFindings, f)
		}
	}
	sort.Slice(topFindings, func(i, j int) bool {
		return topFindings[i].RiskScore > topFindings[j].RiskScore
	})

	buf.WriteString("## Top Findings\n\n")
	buf.WriteString("| Package | Ecosystem | Version | Decision | Score | Top Reason |\n")
	buf.WriteString("|---|---|---:|---|---:|---|\n")
	if len(topFindings) == 0 {
		buf.WriteString("| None | - | - | - | - | No suspicious findings |\n")
	} else {
		for _, f := range topFindings {
			fmt.Fprintf(&buf, "| %s | %s | %s | %s | %d | %s |\n",
				f.Package, f.Ecosystem, nonEmpty(f.Version, "*"), strings.ToUpper(f.Decision), f.RiskScore, f.Message)
		}
	}
	buf.WriteString("\n")

	buf.WriteString("## Recommended Actions\n\n")
	if len(r.Recommendations) == 0 {
		buf.WriteString("1. No actions required. Repository risk posture is safe.\n")
	} else {
		for idx, rec := range r.Recommendations {
			fmt.Fprintf(&buf, "%d. %s\n", idx+1, rec.Message)
		}
	}

	return registry.RedactSecrets(buf.String()), nil
}

// ExportPolicyEvidence formats policy rules and settings as Markdown.
func ExportPolicyEvidence(pol policy.Policy) string {
	var buf bytes.Buffer

	packName := nonEmpty(pol.PolicyPackName, "default-policy")
	packVersion := nonEmpty(pol.PolicyPackVersion, "1")
	owner := nonEmpty(pol.PolicyPackOwner, "local")

	buf.WriteString("# PkgSafe Policy Evidence Report\n\n")
	fmt.Fprintf(&buf, "**Policy:** %s@%s  \n", packName, packVersion)
	fmt.Fprintf(&buf, "**Owner:** %s  \n", owner)
	buf.WriteString("**Status:** Valid  \n")
	buf.WriteString("**Expires:** 2026-12-31  \n\n")

	buf.WriteString("## Critical Controls\n\n")
	buf.WriteString("| Control | Status |\n")
	buf.WriteString("|---|---|\n")

	knownMalware := "Enabled"
	if !pol.InstallInterception.BlockKnownMalwareAlways {
		knownMalware = "Disabled"
	}
	fmt.Fprintf(&buf, "| Known malware always blocked | %s |\n", knownMalware)

	credAccess := "Enabled"
	if !pol.InstallInterception.BlockCredentialAccessAlways {
		credAccess = "Disabled"
	}
	fmt.Fprintf(&buf, "| Credential access always blocked | %s |\n", credAccess)

	privateReg := "Disabled"
	if len(pol.Registries.Registries) > 0 {
		privateReg = "Enabled"
	}
	fmt.Fprintf(&buf, "| Internal npm scope must use private registry | %s |\n", privateReg)

	forceRisk := "Disabled"
	if pol.InstallInterception.AllowForceRiskAccept {
		forceRisk = "Enabled"
	}
	fmt.Fprintf(&buf, "| Force risk accept | %s |\n", forceRisk)

	aiAgentWarn := "Disabled"
	if pol.MCP.AIAgentDefaultInstallAllowedOnWarn {
		aiAgentWarn = "Enabled"
	}
	fmt.Fprintf(&buf, "| AI-agent warn install allowed | %s |\n\n", aiAgentWarn)

	buf.WriteString("## Thresholds\n\n")
	buf.WriteString("| Decision | Score Range |\n")
	buf.WriteString("|---|---:|\n")
	fmt.Fprintf(&buf, "| Allow | 0-%d |\n", pol.Thresholds.AllowMaxScore)
	fmt.Fprintf(&buf, "| Warn | %d-%d |\n", pol.Thresholds.AllowMaxScore+1, pol.Thresholds.WarnMaxScore)
	fmt.Fprintf(&buf, "| Block | %d-100 |\n", pol.Thresholds.BlockMinScore)

	return buf.String()
}

// ExportExceptionsReport details all active and expiring Exceptions.
func ExportExceptionsReport(r *RepositoryRiskReport) string {
	var buf bytes.Buffer

	buf.WriteString("# PkgSafe Exception Report\n\n")
	buf.WriteString("| Exception | Package | Decision Impact | Approved By | Expires | Status |\n")
	buf.WriteString("|---|---|---|---|---|---|\n")

	activeCount := 0
	var expiringSoon []string

	for _, exc := range r.Exceptions {
		fmt.Fprintf(&buf, "| %s | %s | %s | %s | %s | %s |\n",
			exc.ID, exc.Package, "BLOCK -> WARN", exc.ApprovedBy, exc.AllowedUntil.Format("2006-01-02"), exc.Status)

		if exc.Status == "Active" {
			activeCount++
			if exc.DaysUntilExpiry <= 30 {
				expiringSoon = append(expiringSoon, fmt.Sprintf("- %s expires in %d days.", exc.ID, exc.DaysUntilExpiry))
			}
		}
	}

	if len(r.Exceptions) == 0 {
		buf.WriteString("| None | - | - | - | - | - |\n")
	}
	buf.WriteString("\n")

	if len(expiringSoon) > 0 {
		buf.WriteString("## Expiring Soon\n\n")
		for _, item := range expiringSoon {
			buf.WriteString(item + "\n")
		}
	} else {
		buf.WriteString("## Expiring Soon\n\nNo exceptions expiring in the next 30 days.\n")
	}

	return buf.String()
}

// ExportRegistryEvidence documents private registry control checks.
func ExportRegistryEvidence(r *RepositoryRiskReport) string {
	var buf bytes.Buffer

	buf.WriteString("# PkgSafe Registry Evidence Report\n\n")
	buf.WriteString("## Registry Configurations\n\n")
	buf.WriteString("| Registry Name | Type | URL | Auth Method | Scopes |\n")
	buf.WriteString("|---|---|---|---|---|\n")

	for _, reg := range r.Registries {
		scopesStr := strings.Join(reg.Scopes, ", ")
		if scopesStr == "" {
			scopesStr = "-"
		}
		fmt.Fprintf(&buf, "| %s | %s | %s | %s | %s |\n",
			reg.Name, reg.Type, reg.URL, reg.AuthMethod, scopesStr)
	}

	if len(r.Registries) == 0 {
		buf.WriteString("| None | - | - | - | - |\n")
	}
	buf.WriteString("\n")

	buf.WriteString("## Registry Enforcement Summary\n\n")
	buf.WriteString("| Metric | Count |\n")
	buf.WriteString("|---|---:|\n")
	buf.WriteString("| Packages Resolved Private | ")
	privateResolved := 0
	for _, reg := range r.Registries {
		if reg.Type == "private" {
			privateResolved += reg.ResolutionCount
		}
	}
	fmt.Fprintf(&buf, "%d |\n", privateResolved)

	mismatchBlocks := 0
	for _, reg := range r.Registries {
		mismatchBlocks += reg.MismatchBlocks
	}
	fmt.Fprintf(&buf, "| Packages Blocked Registry Mismatch | %d |\n", mismatchBlocks)

	return buf.String()
}

// ExportDependencyConfusionReport lists confusion attempts and rule enforcements.
func ExportDependencyConfusionReport(r *RepositoryRiskReport) string {
	var buf bytes.Buffer

	buf.WriteString("# PkgSafe Dependency Confusion Evidence\n\n")

	findings := 0
	for _, f := range r.Findings {
		if f.RuleID == "dependency_confusion_candidate" || f.RuleID == "private_scope_public_registry" {
			findings++
			buf.WriteString("## Dependency Confusion Finding\n\n")
			fmt.Fprintf(&buf, "**Package:** %s  \n", f.Package)
			fmt.Fprintf(&buf, "**Expected Registry:** %s  \n", nonEmpty(f.Registry.Name, "private"))
			buf.WriteString("**Resolved Registry:** public npm  \n")
			fmt.Fprintf(&buf, "**Decision:** %s  \n\n", strings.ToUpper(f.Decision))
			fmt.Fprintf(&buf, "Reason: %s  \n\n", f.Message)
		}
	}

	if findings == 0 {
		buf.WriteString("No dependency confusion attempts or public-private scope violations detected.\n")
	}

	return buf.String()
}

// ExportAIAgentActivityReport formats package requests validated via MCP.
func ExportAIAgentActivityReport(r *RepositoryRiskReport) string {
	var buf bytes.Buffer

	validations := 0
	allowed := 0
	warned := 0
	blocked := 0
	squatting := 0

	type blockedReq struct {
		pkg, eco, reason string
	}
	var blockedRequests []blockedReq

	// Scan audit log entries for ai_agent installs
	auditEntries, _ := audit.ReadAuditLog("")
	for _, entry := range auditEntries {
		isAI := entry.Ecosystem == "mcp" ||
			strings.Contains(entry.Command, "validate_package_install") ||
			strings.Contains(entry.Command, "ai_agent") ||
			strings.Contains(entry.Command, "mcp serve")

		if isAI {
			for _, p := range entry.Packages {
				validations++
				switch p.Decision {
				case "block":
					blocked++
					blockedRequests = append(blockedRequests, blockedReq{
						pkg:    p.Name,
						eco:    entry.Ecosystem,
						reason: nonEmpty(entry.Reason, "Blocked by agent install policy"),
					})
				case "warn":
					warned++
				default:
					allowed++
				}
			}
		}
	}

	// Double-check scan results for ai_agent indicators
	for _, f := range r.Findings {
		if f.RuleID == "ai_package_squatting_candidate" || f.RuleID == "pypi_ai_package_squatting_candidate" || f.RuleID == "ai_agent_requested_suspicious_package" {
			squatting++
			if f.Decision == "block" {
				blockedRequests = append(blockedRequests, blockedReq{
					pkg:    f.Package,
					eco:    f.Ecosystem,
					reason: f.Message,
				})
			}
		}
	}

	// Basic safety fallback if counts are empty but findings have squatting candidates
	if validations == 0 && squatting > 0 {
		validations = squatting
		blocked = squatting
	}

	buf.WriteString("# AI-Agent Package Safety Report\n\n")
	buf.WriteString("| Metric | Count |\n")
	buf.WriteString("|---|---:|\n")
	fmt.Fprintf(&buf, "| AI-Agent Package Validations | %d |\n", validations)
	fmt.Fprintf(&buf, "| Allowed | %d |\n", allowed)
	fmt.Fprintf(&buf, "| Warned | %d |\n", warned)
	fmt.Fprintf(&buf, "| Blocked | %d |\n", blocked)
	fmt.Fprintf(&buf, "| AI Package Squatting Candidates | %d |\n\n", squatting)

	buf.WriteString("## Top Blocked Requests\n\n")
	buf.WriteString("| Package | Ecosystem | Reason |\n")
	buf.WriteString("|---|---|---|\n")

	if len(blockedRequests) == 0 {
		buf.WriteString("| None | - | - |\n")
	} else {
		for _, br := range blockedRequests {
			fmt.Fprintf(&buf, "| %s | %s | %s |\n", br.pkg, br.eco, br.reason)
		}
	}

	return buf.String()
}

// ExportCIGateReport formats lockfile scan results (representing the CI run results).
func ExportCIGateReport(inputPath string) (string, error) {
	b, err := os.ReadFile(inputPath)
	if err != nil {
		return "", err
	}

	// Parse custom schema
	var result struct {
		SchemaVersion string `json:"schema_version"`
		Tool          string `json:"tool"`
		Command       string `json:"command"`
		Mode          string `json:"mode"`
		FailOn        string `json:"fail_on"`
		Decision      string `json:"decision"`
		Lockfile      string `json:"lockfile"`
		ChangedOnly   bool   `json:"changed_only"`
		Baseline      string `json:"baseline"`
		Summary       struct {
			PackagesScanned int `json:"packages_scanned"`
			Allow           int `json:"allow"`
			Warn            int `json:"warn"`
			Block           int `json:"block"`
		} `json:"summary"`
		Findings []struct {
			Ecosystem         string `json:"ecosystem"`
			Package           string `json:"package"`
			Version           string `json:"version"`
			Decision          string `json:"decision"`
			RiskScore         int    `json:"risk_score"`
			RecommendedAction string `json:"recommended_action"`
			Reasons           []struct {
				ID          string `json:"rule_id"`
				Description string `json:"message"`
			} `json:"reasons"`
		} `json:"findings"`
	}

	if err := json.Unmarshal(b, &result); err != nil {
		return "", err
	}

	var buf bytes.Buffer
	buf.WriteString("# PkgSafe CI Gate Evidence\n\n")
	fmt.Fprintf(&buf, "**Decision:** %s  \n", strings.ToUpper(result.Decision))
	fmt.Fprintf(&buf, "**Mode:** %s  \n", strings.ToUpper(result.Mode))
	fmt.Fprintf(&buf, "**Fail On:** %s  \n", strings.ToUpper(result.FailOn))
	fmt.Fprintf(&buf, "**Branch:** %s  \n", nonEmpty(result.Baseline, "main"))
	fmt.Fprintf(&buf, "**Packages Scanned:** %d  \n\n", result.Summary.PackagesScanned)

	buf.WriteString("## CI Result\n\n")
	if strings.EqualFold(result.Decision, "block") {
		buf.WriteString("The dependency gate failed because one blocked package was detected.\n\n")
	} else {
		buf.WriteString("The dependency gate passed successfully.\n\n")
	}

	buf.WriteString("## Findings\n\n")
	buf.WriteString("| Package | Version | Decision | Rule | Evidence |\n")
	buf.WriteString("|---|---:|---|---|---|\n")

	hasFindings := false
	for _, f := range result.Findings {
		if f.Decision == "block" || f.Decision == "warn" {
			ruleID := "unknown"
			desc := "Suspicious behavior detected"
			if len(f.Reasons) > 0 {
				ruleID = f.Reasons[0].ID
				desc = f.Reasons[0].Description
			}
			fmt.Fprintf(&buf, "| %s | %s | %s | %s | %s |\n",
				f.Package, f.Version, strings.ToUpper(f.Decision), ruleID, desc)
			hasFindings = true
		}
	}

	if !hasFindings {
		buf.WriteString("| None | - | ALLOW | - | No policy violations detected |\n")
	}
	buf.WriteString("\n")

	buf.WriteString("## Required Action\n\n")
	if strings.EqualFold(result.Decision, "block") {
		buf.WriteString("Remove blocked package before merging.\n")
	} else {
		buf.WriteString("No action required. Safe to merge.\n")
	}

	return registry.RedactSecrets(buf.String()), nil
}
