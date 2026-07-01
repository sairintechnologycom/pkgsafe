package report

import (
	"encoding/json"
	"fmt"

	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

// ExportServiceNow compiles the ServiceNow evidence payload.
func ExportServiceNow(r *RepositoryRiskReport) (string, error) {
	overall := "allow"
	if r.Summary.Blocked > 0 {
		overall = "block"
	} else if r.Summary.Warnings > 0 {
		overall = "warn"
	}

	var requiredActions []string
	for _, f := range r.Findings {
		if f.Decision == "block" {
			requiredActions = append(requiredActions, fmt.Sprintf("Remove blocked dependency %s@%s", f.Package, f.Version))
		}
	}
	for _, exc := range r.Exceptions {
		if exc.Status == "Active" && exc.DaysUntilExpiry <= 30 {
			requiredActions = append(requiredActions, fmt.Sprintf("Review exception %s before expiry", exc.ID))
		}
	}
	if len(requiredActions) == 0 {
		requiredActions = append(requiredActions, "No remediation actions required.")
	}

	payload := map[string]any{
		"tool":             "PkgSafe",
		"report_type":      "software_supply_chain_evidence",
		"generated_at":     r.GeneratedAt,
		"repository":       r.Repository.Name,
		"overall_decision": overall,
		"policy_pack":      r.Policy.PackName + "@" + r.Policy.PackVersion,
		"summary": map[string]any{
			"packages_scanned":         r.Summary.PackagesScanned,
			"allowed":                  r.Summary.Allowed,
			"warned":                   r.Summary.Warnings,
			"blocked":                  r.Summary.Blocked,
			"critical_vulnerabilities": r.Summary.CriticalVulnerabilities,
			"high_vulnerabilities":     r.Summary.HighVulnerabilities,
			"exceptions_used":          r.Summary.ActiveExceptions,
			"overrides_used":           r.Summary.DeveloperOverrides,
		},
		"controls_validated": []string{
			"Known malware block policy",
			"Private registry enforcement",
			"Dependency confusion detection",
			"Credential access detection",
			"AI-agent install guardrail",
		},
		"required_actions": requiredActions,
		"attachment_files": []string{
			"pkgsafe-report.md",
			"pkgsafe-results.json",
			"pkgsafe-results.sarif",
		},
	}

	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return registry.RedactSecrets(string(b)), nil
}
