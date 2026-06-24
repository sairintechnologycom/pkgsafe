package report

import (
	"bytes"
	"encoding/json"

	"github.com/niyam-ai/pkgsafe/internal/registry"
)

// ExportSIEM formats the risk events in JSONL for SIEM intake.
func ExportSIEM(r *RepositoryRiskReport) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	// Keep track of emitted packages to prevent duplicates
	emitted := make(map[string]bool)

	for _, f := range r.Findings {
		key := f.Ecosystem + ":" + f.Package + "@" + f.Version
		if emitted[key] {
			continue
		}
		emitted[key] = true

		severity := f.Severity
		if severity == "" {
			severity = "medium"
		}

		// Base event
		evt := SIEMEvent{
			Timestamp:  r.GeneratedAt,
			Severity:   severity,
			Tool:       "pkgsafe",
			Ecosystem:  f.Ecosystem,
			Package:    f.Package,
			Version:    f.Version,
			Decision:   f.Decision,
			RiskScore:  f.RiskScore,
			RuleID:     f.RuleID,
			Repository: r.Repository.Name,
			PolicyPack: r.Policy.PackName + "@" + r.Policy.PackVersion,
			Message:    f.Message,
		}

		if f.Decision == "block" {
			evt.EventType = "package_blocked"
			_ = enc.Encode(evt)

			// Secondary specific alerts
			if f.RuleID == "known_malware_indicator" || f.RuleID == "blocked_package" {
				evt2 := evt
				evt2.EventType = "known_malware_detected"
				evt2.Severity = "critical"
				_ = enc.Encode(evt2)
			}
			if f.RuleID == "credential_canary_read" || f.RuleID == "credential_path_reference" || f.RuleID == "pypi_setup_py_credential_access" {
				evt2 := evt
				evt2.EventType = "credential_access_detected"
				evt2.Severity = "critical"
				_ = enc.Encode(evt2)
			}
			if f.RuleID == "dependency_confusion_candidate" {
				evt2 := evt
				evt2.EventType = "dependency_confusion_detected"
				evt2.Severity = "critical"
				_ = enc.Encode(evt2)
			}
			if f.RuleID == "private_scope_public_registry" || f.RuleID == "unapproved_registry_url" {
				evt2 := evt
				evt2.EventType = "private_registry_violation"
				evt2.Severity = "critical"
				_ = enc.Encode(evt2)
			}
		} else if f.Decision == "warn" {
			evt.EventType = "package_warned"
			_ = enc.Encode(evt)
		}

		if f.Exception.Matched {
			evt2 := evt
			evt2.EventType = "policy_exception_used"
			evt2.Severity = "low"
			evt2.Message = "Exception used: " + f.Exception.Reason
			_ = enc.Encode(evt2)
		}

		if f.Override.Used {
			evt2 := evt
			evt2.EventType = "developer_override_used"
			evt2.Severity = "high"
			evt2.Message = "Override used: " + f.Override.Reason
			_ = enc.Encode(evt2)
		}
	}

	// CI Gate failed event
	if r.Summary.Blocked > 0 {
		gateEvt := SIEMEvent{
			Timestamp:  r.GeneratedAt,
			EventType:  "ci_gate_failed",
			Severity:   "high",
			Tool:       "pkgsafe",
			Repository: r.Repository.Name,
			PolicyPack: r.Policy.PackName + "@" + r.Policy.PackVersion,
			Message:    "CI dependency gate failed due to blocked packages.",
		}
		_ = enc.Encode(gateEvt)
	}

	return registry.RedactSecrets(buf.String()), nil
}
