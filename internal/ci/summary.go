package ci

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func WriteHumanSummary(w io.Writer, result *ScanResult) {
	fmt.Fprintln(w, "PkgSafe CI Package Gate")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(result.Decision))
	fmt.Fprintf(w, "Mode: %s\n", strings.ToUpper(result.Mode))
	fmt.Fprintf(w, "Fail On: %s\n", strings.ToUpper(result.FailOn))
	if result.Ecosystem != "" {
		fmt.Fprintf(w, "Ecosystem: %s\n", result.Ecosystem)
	}
	if len(result.DependencyFiles) > 0 {
		fmt.Fprintf(w, "Dependency Files: %s\n", strings.Join(result.DependencyFiles, ", "))
	} else {
		fmt.Fprintf(w, "Lockfile: %s\n", result.Lockfile)
	}
	fmt.Fprintf(w, "Changed Only: %v\n", result.ChangedOnly)
	if result.PolicyPack != "" {
		fmt.Fprintf(w, "Policy Pack: %s@%s\n", result.PolicyPack, result.PolicyPackVersion)
	}
	if len(result.ExceptionsUsed) > 0 {
		fmt.Fprintf(w, "Exceptions Used: %s\n", strings.Join(result.ExceptionsUsed, ", "))
	}
	fmt.Fprintf(w, "Packages Scanned: %d\n", result.Summary.PackagesScanned)
	if result.ChangedOnly && result.Summary.PackagesScanned == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "NOTICE: changed-only scan found 0 packages.")
		fmt.Fprintln(w, "        Decision ALLOW means no dependency changes were gated — not that the full project is clean.")
		fmt.Fprintln(w, "        Run with --changed-only=false for a full lockfile scan.")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Summary:")
	fmt.Fprintf(w, "- Allow: %d\n", result.Summary.Allow)
	fmt.Fprintf(w, "- Warn: %d\n", result.Summary.Warn)
	fmt.Fprintf(w, "- Block: %d\n", result.Summary.Block)
	fmt.Fprintf(w, "- Review Required: %d\n", result.Summary.ReviewRequired)
	fmt.Fprintf(w, "- Vulnerabilities: %d\n", result.Summary.VulnerabilityCount)
	if len(result.Summary.VulnerabilitiesBySeverity) > 0 {
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count := result.Summary.VulnerabilitiesBySeverity[sev]; count > 0 {
				fmt.Fprintf(w, "  - %s: %d\n", sev, count)
			}
		}
	}
	fmt.Fprintln(w)

	// Filter and sort top findings (warn or block)
	var topFindings []Finding
	for _, f := range result.Findings {
		if f.Decision == "block" || f.Decision == "warn" || f.Decision == "review_required" {
			topFindings = append(topFindings, f)
		}
	}
	sort.Slice(topFindings, func(i, j int) bool {
		return topFindings[i].RiskScore > topFindings[j].RiskScore
	})

	if len(topFindings) > 0 {
		fmt.Fprintln(w, "Top Findings:")
		for i, f := range topFindings {
			topReason := "No specific risk reason found"
			maxImpact := -999
			for _, r := range f.Reasons {
				if r.ScoreImpact > maxImpact {
					maxImpact = r.ScoreImpact
					topReason = r.Description
				}
			}
			fmt.Fprintf(w, "%d. %s@%s\n", i+1, f.Package, f.Version)
			fmt.Fprintf(w, "   Decision: %s\n", strings.ToUpper(f.Decision))
			fmt.Fprintf(w, "   Score: %d\n", f.RiskScore)
			fmt.Fprintf(w, "   Reason: %s\n", topReason)
			fmt.Fprintln(w)
		}
	}

	if result.Summary.VulnerabilityCount > 0 {
		fmt.Fprintln(w, "Vulnerability Summary:")
		for _, f := range topVulnerableFindings(result.Findings, 5) {
			fmt.Fprintf(w, "- %s@%s: %d advisory(s)\n", f.Package, f.Version, len(f.Vulnerabilities))
			for _, v := range f.Vulnerabilities {
				fixed := ""
				if len(v.FixedVersions) > 0 {
					fixed = fmt.Sprintf(" fixed in %s", strings.Join(v.FixedVersions, ", "))
				}
				fmt.Fprintf(w, "  - %s [%s]%s: %s\n", v.ID, v.Severity, fixed, v.Summary)
			}
		}
		if len(result.Summary.FixedVersionRecommendations) > 0 {
			fmt.Fprintln(w, "Fixed Version Recommendations:")
			for _, rec := range result.Summary.FixedVersionRecommendations {
				fmt.Fprintf(w, "- %s\n", rec)
			}
		}
		fmt.Fprintln(w)
	}

	var registryMismatches []string
	var dependencyConfusions []string
	for _, f := range result.Findings {
		for _, r := range f.Reasons {
			if r.ID == "private_scope_public_registry" || r.ID == "unapproved_registry_url" {
				registryMismatches = append(registryMismatches, fmt.Sprintf("%s@%s (%s)", f.Package, f.Version, r.Description))
			}
			if r.ID == "dependency_confusion_candidate" {
				dependencyConfusions = append(dependencyConfusions, fmt.Sprintf("%s@%s (%s)", f.Package, f.Version, r.Description))
			}
		}
	}

	if len(registryMismatches) > 0 {
		fmt.Fprintln(w, "Private Registry Mismatches:")
		for _, m := range uniqueStrings(registryMismatches) {
			fmt.Fprintf(w, "- %s\n", m)
		}
		fmt.Fprintln(w)
	}
	if len(dependencyConfusions) > 0 {
		fmt.Fprintln(w, "Dependency Confusion Candidates:")
		for _, c := range uniqueStrings(dependencyConfusions) {
			fmt.Fprintf(w, "- %s\n", c)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Recommended Action:")
	if result.Decision == "block" {
		fmt.Fprintln(w, "Remove or replace blocked dependencies before merging.")
	} else if result.Decision == "review_required" {
		fmt.Fprintln(w, "Request authorized human review before merging.")
	} else if result.Decision == "warn" {
		fmt.Fprintln(w, "Review package warnings before merging.")
	} else if result.ChangedOnly && result.Summary.PackagesScanned == 0 {
		fmt.Fprintln(w, "No dependency changes to gate. Use a full scan if you need whole-lockfile coverage.")
	} else {
		fmt.Fprintln(w, "Package scan completed successfully. No action required.")
	}
}

func WriteJSONOutput(path string, result *ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// SARIF definition structs
type SarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}
type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}
type SarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}
type SarifRule struct {
	ID               string           `json:"id"`
	ShortDescription SarifDescription `json:"shortDescription"`
}
type SarifDescription struct {
	Text string `json:"text"`
}
type SarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SarifMessage      `json:"message"`
	Locations           []SarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}
type SarifMessage struct {
	Text string `json:"text"`
}
type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}
type SarifArtifactLocation struct {
	URI string `json:"uri"`
}
type SarifRegion struct {
	StartLine int `json:"startLine"`
}

func WriteSarifOutput(path string, result *ScanResult) error {
	rules := []SarifRule{}
	results := []SarifResult{}
	ruleSeen := make(map[string]bool)

	addRule := func(id, desc string) {
		if id == "" {
			return
		}
		if !ruleSeen[id] {
			ruleSeen[id] = true
			rules = append(rules, SarifRule{
				ID:               id,
				ShortDescription: SarifDescription{Text: desc},
			})
		}
	}

	for _, f := range result.Findings {
		// Report each reason as a SARIF finding
		for _, r := range f.Reasons {
			if r.ID == "" {
				continue
			}
			addRule(r.ID, r.Description)
			level := severityToSarifLevel(r.Severity)

			results = append(results, SarifResult{
				RuleID: r.ID,
				Level:  level,
				Message: SarifMessage{
					Text: fmt.Sprintf("%s in package %s@%s: %s", r.ID, f.Package, f.Version, r.Description),
				},
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{URI: artifactURI(result)},
							Region: &SarifRegion{
								StartLine: 1,
							},
						},
					},
				},
				PartialFingerprints: map[string]string{
					"package": f.Package,
					"version": f.Version,
				},
			})
		}

		// Also report vulnerabilities
		for _, v := range f.Vulnerabilities {
			ruleID := v.ID
			if ruleID == "" {
				ruleID = "known_vulnerability_" + v.Severity
			}
			fixed := ""
			if len(v.FixedVersions) > 0 {
				fixed = " Fixed in: " + strings.Join(v.FixedVersions, ", ") + "."
			}
			addRule(ruleID, "Known Vulnerability: "+v.Summary)
			level := severityToSarifLevel(v.Severity)

			results = append(results, SarifResult{
				RuleID: ruleID,
				Level:  level,
				Message: SarifMessage{
					Text: fmt.Sprintf("Known advisory %s (%s) affects %s@%s: %s.%s", v.ID, v.Severity, f.Package, f.Version, v.Summary, fixed),
				},
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{URI: artifactURI(result)},
							Region: &SarifRegion{
								StartLine: 1,
							},
						},
					},
				},
				PartialFingerprints: map[string]string{
					"package": f.Package,
					"version": f.Version,
				},
			})
		}
	}

	report := SarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "PkgSafe",
						InformationURI: "https://github.com/your-org/pkgsafe",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func artifactURI(result *ScanResult) string {
	if len(result.DependencyFiles) > 0 {
		return result.DependencyFiles[0]
	}
	return result.Lockfile
}

func severityToSarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info", "informational":
		return "note"
	default:
		return "note"
	}
}

func WriteSummaryOutput(path string, result *ScanResult) error {
	var sb strings.Builder

	sb.WriteString("## PkgSafe Dependency Gate\n\n")
	fmt.Fprintf(&sb, "**Decision:** %s  \n", strings.ToUpper(result.Decision))
	fmt.Fprintf(&sb, "**Mode:** %s  \n", strings.ToUpper(result.Mode))
	fmt.Fprintf(&sb, "**Fail On:** %s  \n", strings.ToUpper(result.FailOn))
	fmt.Fprintf(&sb, "**Workflow Result:** %s  \n", workflowResultText(result))
	if result.PolicyPack != "" {
		fmt.Fprintf(&sb, "**Policy Pack:** %s@%s  \n", result.PolicyPack, result.PolicyPackVersion)
	}
	if len(result.ExceptionsUsed) > 0 {
		fmt.Fprintf(&sb, "**Exceptions Used:** %s  \n", strings.Join(result.ExceptionsUsed, ", "))
	}
	if result.Ecosystem != "" {
		fmt.Fprintf(&sb, "**Ecosystem:** %s  \n", result.Ecosystem)
	}
	if len(result.DependencyFiles) > 0 {
		fmt.Fprintf(&sb, "**Dependency Files:** %s  \n", strings.Join(result.DependencyFiles, ", "))
	} else if result.Lockfile != "" {
		fmt.Fprintf(&sb, "**Lockfile:** %s  \n", result.Lockfile)
	}
	fmt.Fprintf(&sb, "**Changed Only:** %t  \n", result.ChangedOnly)
	if result.Baseline != "" {
		fmt.Fprintf(&sb, "**Baseline:** %s", result.Baseline)
		if result.BaselineType != "" {
			fmt.Fprintf(&sb, " (%s)", result.BaselineType)
		}
		sb.WriteString("  \n")
	}
	fmt.Fprintf(&sb, "**Packages Scanned:** %d  \n\n", result.Summary.PackagesScanned)

	sb.WriteString("### Counts\n\n")
	sb.WriteString("| Allow | Warn | Review Required | Block | Unknown | Vulnerabilities |\n")
	sb.WriteString("|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(&sb, "| %d | %d | %d | %d | %d | %d |\n\n", result.Summary.Allow, result.Summary.Warn, result.Summary.ReviewRequired, result.Summary.Block, result.Summary.Unknown, result.Summary.VulnerabilityCount)
	if result.Summary.VulnerabilityCount > 0 {
		fmt.Fprintf(&sb, "**Vulnerabilities:** %d  \n", result.Summary.VulnerabilityCount)
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count := result.Summary.VulnerabilitiesBySeverity[sev]; count > 0 {
				fmt.Fprintf(&sb, "- %s: %d\n", sev, count)
			}
		}
		sb.WriteString("\n")
	}

	var issues []Finding
	for _, f := range result.Findings {
		if f.Decision == "block" || f.Decision == "warn" || f.Decision == "review_required" {
			issues = append(issues, f)
		}
	}

	if len(issues) > 0 {
		sort.Slice(issues, func(i, j int) bool {
			return issues[i].RiskScore > issues[j].RiskScore
		})

		sb.WriteString("### Warn / Review / Block Findings\n\n")
		sb.WriteString("| Package | Version | Decision | Score | Top Reason |\n")
		sb.WriteString("|---|---:|---|---:|---|\n")
		for _, f := range issues {
			topReason := "No specific risk reason found"
			maxImpact := -999
			for _, r := range f.Reasons {
				if r.ScoreImpact > maxImpact {
					maxImpact = r.ScoreImpact
					topReason = r.Description
				}
			}
			fmt.Fprintf(&sb, "| %s | %s | %s | %d | %s |\n", f.Package, f.Version, strings.ToUpper(f.Decision), f.RiskScore, topReason)
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("### Warn / Review / Block Findings\n\n")
		sb.WriteString("No blocked, review-required, or warning dependencies found.\n\n")
	}

	if result.Summary.VulnerabilityCount > 0 {
		sb.WriteString("### Vulnerabilities\n\n")
		sb.WriteString("| Package | Version | Advisory | Severity | Fixed Versions |\n")
		sb.WriteString("|---|---:|---|---|---|\n")
		for _, f := range topVulnerableFindings(result.Findings, 10) {
			for _, v := range f.Vulnerabilities {
				fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n", f.Package, f.Version, v.ID, v.Severity, strings.Join(v.FixedVersions, ", "))
			}
		}
		sb.WriteString("\n")
		if len(result.Summary.FixedVersionRecommendations) > 0 {
			sb.WriteString("### Fixed Version Recommendations\n\n")
			for _, rec := range result.Summary.FixedVersionRecommendations {
				fmt.Fprintf(&sb, "- %s\n", rec)
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("### Recommended Action\n\n")
	if result.Decision == "block" {
		sb.WriteString("Remove or replace blocked dependencies before merging. With `fail-on: block`, this workflow fails for BLOCK findings.\n")
	} else if result.Decision == "review_required" {
		if result.FailOn == "warn" {
			sb.WriteString("Request authorized human review before merging. With `fail-on: warn`, this workflow fails for REVIEW_REQUIRED, WARN, and BLOCK findings.\n")
		} else {
			sb.WriteString("Request authorized human review before merging. With `fail-on: block`, REVIEW_REQUIRED findings are reported without auto-merge approval.\n")
		}
	} else if result.Decision == "warn" {
		if result.FailOn == "warn" {
			sb.WriteString("Review warning dependencies before merging. With `fail-on: warn`, this workflow fails for WARN and BLOCK findings.\n")
		} else {
			sb.WriteString("Review warning dependencies before merging. With `fail-on: block`, WARN findings are reported without failing the workflow.\n")
		}
	} else {
		sb.WriteString("All scanned packages are allowed by policy.\n")
	}
	sb.WriteString("\n")

	var registryMismatches []string
	var dependencyConfusions []string
	for _, f := range result.Findings {
		for _, r := range f.Reasons {
			if r.ID == "private_scope_public_registry" || r.ID == "unapproved_registry_url" {
				registryMismatches = append(registryMismatches, fmt.Sprintf("%s@%s (%s)", f.Package, f.Version, r.Description))
			}
			if r.ID == "dependency_confusion_candidate" {
				dependencyConfusions = append(dependencyConfusions, fmt.Sprintf("%s@%s (%s)", f.Package, f.Version, r.Description))
			}
		}
	}

	if len(registryMismatches) > 0 {
		sb.WriteString("### Private Registry Mismatches\n\n")
		for _, m := range uniqueStrings(registryMismatches) {
			fmt.Fprintf(&sb, "- %s\n", m)
		}
		sb.WriteString("\n")
	}
	if len(dependencyConfusions) > 0 {
		sb.WriteString("### Dependency Confusion Candidates\n\n")
		for _, c := range uniqueStrings(dependencyConfusions) {
			fmt.Fprintf(&sb, "- %s\n", c)
		}
		sb.WriteString("\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func workflowResultText(result *ScanResult) string {
	switch result.FailOn {
	case "warn":
		if result.Decision == "warn" || result.Decision == "block" || result.Decision == "review_required" {
			return "fails on REVIEW_REQUIRED, WARN, or BLOCK"
		}
	case "block":
		if result.Decision == "block" || result.Decision == "review_required" {
			return "fails on REVIEW_REQUIRED or BLOCK"
		}
	case "none":
		return "reports only"
	}
	return "passes"
}

func topVulnerableFindings(findings []Finding, limit int) []Finding {
	var out []Finding
	for _, f := range findings {
		if len(f.Vulnerabilities) > 0 {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Vulnerabilities) == len(out[j].Vulnerabilities) {
			return out[i].RiskScore > out[j].RiskScore
		}
		return len(out[i].Vulnerabilities) > len(out[j].Vulnerabilities)
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}
