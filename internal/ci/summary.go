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
	fmt.Fprintf(w, "Packages Scanned: %d\n", result.Summary.PackagesScanned)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Summary:")
	fmt.Fprintf(w, "- Allow: %d\n", result.Summary.Allow)
	fmt.Fprintf(w, "- Warn: %d\n", result.Summary.Warn)
	fmt.Fprintf(w, "- Block: %d\n", result.Summary.Block)
	fmt.Fprintln(w)

	// Filter and sort top findings (warn or block)
	var topFindings []Finding
	for _, f := range result.Findings {
		if f.Decision == "block" || f.Decision == "warn" {
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

	fmt.Fprintln(w, "Recommended Action:")
	if result.Decision == "block" {
		fmt.Fprintln(w, "Remove or replace blocked dependencies before merging.")
	} else if result.Decision == "warn" {
		fmt.Fprintln(w, "Review package warnings before merging.")
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
	var rules []SarifRule
	var results []SarifResult
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
			ruleID := "known_vulnerability_" + v.Severity
			addRule(ruleID, "Known Vulnerability: "+v.Summary)
			level := severityToSarifLevel(v.Severity)

			results = append(results, SarifResult{
				RuleID: ruleID,
				Level:  level,
				Message: SarifMessage{
					Text: fmt.Sprintf("Known advisory %s (%s) affects %s@%s: %s", v.ID, v.Severity, f.Package, f.Version, v.Summary),
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
	fmt.Fprintf(&sb, "**Packages Scanned:** %d  \n\n", result.Summary.PackagesScanned)

	var issues []Finding
	for _, f := range result.Findings {
		if f.Decision == "block" || f.Decision == "warn" {
			issues = append(issues, f)
		}
	}

	if len(issues) > 0 {
		sort.Slice(issues, func(i, j int) bool {
			return issues[i].RiskScore > issues[j].RiskScore
		})

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
		sb.WriteString("No blocked or warning dependencies found.\n\n")
	}

	sb.WriteString("### Recommended Action\n\n")
	if result.Decision == "block" {
		sb.WriteString("Remove or replace blocked dependencies before merging.\n")
	} else if result.Decision == "warn" {
		sb.WriteString("Review warning dependencies before merging.\n")
	} else {
		sb.WriteString("All packages are allowed by policy.\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
