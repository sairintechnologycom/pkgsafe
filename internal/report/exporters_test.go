package report

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sampleReport builds a small but representative report covering findings,
// exceptions, and overrides for exporter tests.
func sampleReport() *RepositoryRiskReport {
	return &RepositoryRiskReport{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		Findings: []ReportFinding{
			{
				Ecosystem: "npm", Package: "lodash", Version: "4.17.20",
				Decision: "warn", RiskScore: 55, Severity: "medium",
				RuleID: "known_vulnerability", Message: "prototype pollution",
				Policy:            FindingPolicy{Pack: "default"},
				Registry:          FindingRegistry{Name: "npmjs"},
				RecommendedAction: "Upgrade to 4.17.21",
			},
			{
				Ecosystem: "npm", Package: "@acme/internal", Version: "1.0.0",
				Decision: "block", RiskScore: 90, Severity: "high",
				RuleID:   "dependency_confusion_candidate",
				Message:  "private scope resolved from public registry",
				Registry: FindingRegistry{Name: "acme-private"},
			},
		},
		Exceptions: []ExceptionRecord{
			{
				ID: "EXC-1", Package: "lodash", Ecosystem: "npm",
				VersionRange: "<4.17.21", Reason: "patch scheduled",
				ApprovedBy: "secops", AllowedUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
				Status: "Active", UsedInRecentScans: true,
			},
		},
		Overrides: []OverrideRecord{
			{
				Timestamp: "2026-07-01T00:00:00Z", User: "dev", Repository: "app",
				Command: "npm install", Package: "left-pad", Ecosystem: "npm",
				Version: "1.0.0", Decision: "block", RiskScore: 80,
				OverrideReason: "false positive", PolicyPack: "default",
			},
		},
	}
}

func TestExportCSVAllTypes(t *testing.T) {
	r := sampleReport()
	for _, csvType := range []string{"findings", "exceptions", "overrides", "packages"} {
		out, err := ExportCSV(r, csvType)
		if err != nil {
			t.Fatalf("ExportCSV(%q): %v", csvType, err)
		}
		// Every export must parse as valid CSV with a header + at least one row.
		records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
		if err != nil {
			t.Fatalf("ExportCSV(%q) produced invalid CSV: %v", csvType, err)
		}
		if len(records) < 2 {
			t.Errorf("ExportCSV(%q) expected header + data rows, got %d rows", csvType, len(records))
		}
	}
}

func TestExportCSVContentAndUnsupported(t *testing.T) {
	r := sampleReport()

	findings, err := ExportCSV(r, "findings")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(findings, "lodash") || !strings.Contains(findings, "known_vulnerability") {
		t.Errorf("findings CSV missing expected content:\n%s", findings)
	}

	if _, err := ExportCSV(r, "bogus"); err == nil {
		t.Fatal("expected error for unsupported CSV type")
	}
}

func TestExportCSVRedactsSecrets(t *testing.T) {
	r := sampleReport()
	r.Findings[0].Message = "auth failed for https://user:supersecret@registry.internal/x"

	out, err := ExportCSV(r, "findings")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "supersecret") {
		t.Errorf("CSV export leaked a credential:\n%s", out)
	}
}

func TestSeverityToSarifLevel(t *testing.T) {
	cases := map[string]string{
		"critical":      "error",
		"high":          "error",
		"HIGH":          "error",
		"medium":        "warning",
		"low":           "note",
		"info":          "note",
		"informational": "note",
		"":              "note",
		"weird":         "note",
	}
	for sev, want := range cases {
		if got := severityToSarifLevel(sev); got != want {
			t.Errorf("severityToSarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestExportDependencyConfusionReport(t *testing.T) {
	// With a confusion finding.
	out := ExportDependencyConfusionReport(sampleReport())
	if !strings.Contains(out, "Dependency Confusion Finding") || !strings.Contains(out, "@acme/internal") {
		t.Errorf("expected the confusion finding to be rendered:\n%s", out)
	}

	// Without any confusion findings → explicit "none" message.
	clean := &RepositoryRiskReport{
		Findings: []ReportFinding{{Package: "safe", RuleID: "known_vulnerability"}},
	}
	outClean := ExportDependencyConfusionReport(clean)
	if !strings.Contains(outClean, "No dependency confusion") {
		t.Errorf("expected the empty-state message:\n%s", outClean)
	}
}

func TestExportAIAgentActivityReport(t *testing.T) {
	// Hermetic: point HOME at a temp dir so the audit-log read finds nothing and
	// the report is driven purely by scan findings.
	t.Setenv("HOME", t.TempDir())

	r := &RepositoryRiskReport{
		Findings: []ReportFinding{
			{
				Package: "reqests", Ecosystem: "pypi", Decision: "block",
				RuleID: "pypi_ai_package_squatting_candidate", Message: "typosquat of requests",
			},
		},
	}
	out := ExportAIAgentActivityReport(r)
	if !strings.Contains(out, "AI-Agent Package Safety Report") {
		t.Fatalf("missing report header:\n%s", out)
	}
	if !strings.Contains(out, "reqests") {
		t.Errorf("expected the blocked squatting candidate in the report:\n%s", out)
	}

	// Empty report → the "None" fallback row.
	empty := ExportAIAgentActivityReport(&RepositoryRiskReport{})
	if !strings.Contains(empty, "| None | - | - |") {
		t.Errorf("expected the empty blocked-requests row:\n%s", empty)
	}
}

func writeCIResult(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ci-result.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExportCIGateReportBlock(t *testing.T) {
	body := `{
		"schema_version": "1.0", "tool": "pkgsafe", "command": "ci scan",
		"mode": "block", "fail_on": "block", "decision": "block",
		"lockfile": "package-lock.json", "baseline": "release",
		"summary": {"packages_scanned": 3, "allow": 2, "warn": 0, "block": 1},
		"findings": [
			{"ecosystem":"npm","package":"evil","version":"6.6.6","decision":"block","risk_score":95,
			 "reasons":[{"rule_id":"known_malware","message":"malware signature"}]}
		]
	}`
	out, err := ExportCIGateReport(writeCIResult(t, body))
	if err != nil {
		t.Fatalf("ExportCIGateReport: %v", err)
	}
	for _, want := range []string{"CI Gate Evidence", "**Decision:** BLOCK", "evil", "known_malware", "Remove blocked package"} {
		if !strings.Contains(out, want) {
			t.Errorf("block report missing %q:\n%s", want, out)
		}
	}
}

func TestExportCIGateReportPass(t *testing.T) {
	body := `{
		"decision": "allow", "mode": "warn", "fail_on": "block",
		"summary": {"packages_scanned": 5, "allow": 5},
		"findings": []
	}`
	out, err := ExportCIGateReport(writeCIResult(t, body))
	if err != nil {
		t.Fatalf("ExportCIGateReport: %v", err)
	}
	if !strings.Contains(out, "Safe to merge") || !strings.Contains(out, "No policy violations detected") {
		t.Errorf("pass report missing expected empty-state text:\n%s", out)
	}
	// Branch defaults to "main" when baseline is absent.
	if !strings.Contains(out, "**Branch:** main") {
		t.Errorf("expected default branch fallback:\n%s", out)
	}
}

func TestExportCIGateReportErrors(t *testing.T) {
	if _, err := ExportCIGateReport(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected error for a missing input file")
	}
	if _, err := ExportCIGateReport(writeCIResult(t, "{not valid json")); err == nil {
		t.Error("expected error for malformed JSON")
	}
}
