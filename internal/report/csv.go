package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"

	"github.com/sairintechnologycom/pkgsafe/internal/registry"
)

// ExportCSV formats reports/metadata as CSV strings.
func ExportCSV(r *RepositoryRiskReport, csvType string) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	switch csvType {
	case "findings":
		// ecosystem,package,version,decision,risk_score,severity,rule_id,message,policy_pack,registry,exception_id,override_used,recommended_action
		header := []string{"ecosystem", "package", "version", "decision", "risk_score", "severity", "rule_id", "message", "policy_pack", "registry", "exception_id", "override_used", "recommended_action"}
		if err := w.Write(header); err != nil {
			return "", err
		}
		for _, f := range r.Findings {
			row := []string{
				f.Ecosystem,
				f.Package,
				f.Version,
				f.Decision,
				strconv.Itoa(f.RiskScore),
				f.Severity,
				f.RuleID,
				f.Message,
				f.Policy.Pack,
				f.Registry.Name,
				f.Exception.ID,
				strconv.FormatBool(f.Override.Used),
				f.RecommendedAction,
			}
			if err := w.Write(row); err != nil {
				return "", err
			}
		}

	case "exceptions":
		header := []string{"exception_id", "package", "ecosystem", "version_range", "reason", "approved_by", "allowed_until", "status", "used"}
		if err := w.Write(header); err != nil {
			return "", err
		}
		for _, exc := range r.Exceptions {
			row := []string{
				exc.ID,
				exc.Package,
				exc.Ecosystem,
				exc.VersionRange,
				exc.Reason,
				exc.ApprovedBy,
				exc.AllowedUntil.Format("2006-01-02"),
				exc.Status,
				strconv.FormatBool(exc.UsedInRecentScans),
			}
			if err := w.Write(row); err != nil {
				return "", err
			}
		}

	case "overrides":
		// timestamp,user,repository,command,package,ecosystem,version,decision,risk_score,override_reason,policy_pack
		header := []string{"timestamp", "user", "repository", "command", "package", "ecosystem", "version", "decision", "risk_score", "override_reason", "policy_pack"}
		if err := w.Write(header); err != nil {
			return "", err
		}
		for _, ov := range r.Overrides {
			row := []string{
				ov.Timestamp,
				ov.User,
				ov.Repository,
				ov.Command,
				ov.Package,
				ov.Ecosystem,
				ov.Version,
				ov.Decision,
				strconv.Itoa(ov.RiskScore),
				ov.OverrideReason,
				ov.PolicyPack,
			}
			if err := w.Write(row); err != nil {
				return "", err
			}
		}

	case "packages":
		header := []string{"ecosystem", "package", "version", "decision", "risk_score"}
		if err := w.Write(header); err != nil {
			return "", err
		}
		for _, f := range r.Findings {
			row := []string{
				f.Ecosystem,
				f.Package,
				f.Version,
				f.Decision,
				strconv.Itoa(f.RiskScore),
			}
			if err := w.Write(row); err != nil {
				return "", err
			}
		}

	default:
		return "", fmt.Errorf("unsupported CSV type: %s", csvType)
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	// Scrub any secrets (tokens, credentials, basic-auth URLs) that may have
	// surfaced in free-text fields such as messages or registry URLs. CSV is the
	// last exporter to gain this; every other format already redacts its output.
	return registry.RedactSecrets(buf.String()), nil
}
