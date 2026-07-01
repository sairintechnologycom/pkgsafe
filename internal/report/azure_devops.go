package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

// ExportAzureDevOps formats the supply chain evidence in Azure DevOps Markdown style.
func ExportAzureDevOps(r *RepositoryRiskReport) (string, error) {
	var buf bytes.Buffer

	overall := "ALLOW"
	if r.Summary.Blocked > 0 {
		overall = "BLOCK"
	} else if r.Summary.Warnings > 0 {
		overall = "WARN"
	}

	buf.WriteString("# PkgSafe Supply Chain Evidence\n\n")
	buf.WriteString("## Decision\n\n")
	fmt.Fprintf(&buf, "**Overall:** %s  \n", overall)
	fmt.Fprintf(&buf, "**Policy:** %s@%s  \n", r.Policy.PackName, r.Policy.PackVersion)
	fmt.Fprintf(&buf, "**Packages Scanned:** %d  \n\n", r.Summary.PackagesScanned)

	// Calculate severity counts from findings
	counts := map[string]int{
		"critical":      0,
		"high":          0,
		"medium":        0,
		"low":           0,
		"informational": 0,
	}
	for _, f := range r.Findings {
		counts[strings.ToLower(f.Severity)]++
	}

	buf.WriteString("## Gate Result\n\n")
	buf.WriteString("| Severity | Count |\n")
	buf.WriteString("|---|---:|\n")
	fmt.Fprintf(&buf, "| Critical | %d |\n", counts["critical"])
	fmt.Fprintf(&buf, "| High | %d |\n", counts["high"])
	fmt.Fprintf(&buf, "| Medium | %d |\n", counts["medium"])
	fmt.Fprintf(&buf, "| Low | %d |\n\n", counts["low"])

	buf.WriteString("## Required Actions\n\n")
	actions := 0
	for _, f := range r.Findings {
		if f.Decision == "block" {
			fmt.Fprintf(&buf, "- Remove blocked dependency `%s@%s`\n", f.Package, f.Version)
			actions++
		}
	}
	for _, exc := range r.Exceptions {
		if exc.Status == "Active" && exc.DaysUntilExpiry <= 30 {
			fmt.Fprintf(&buf, "- Review exception `%s`\n", exc.ID)
			actions++
		}
	}
	if actions == 0 {
		buf.WriteString("- No actions required. Repository conforms to policy.\n")
	}

	return registry.RedactSecrets(buf.String()), nil
}
