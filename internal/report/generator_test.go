package report

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestReportGenerationAndExporters(t *testing.T) {
	// Setup temporary workspace and HOME
	tmpDir, err := os.MkdirTemp("", "report-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	// Write mock package-lock.json
	lockContent := `{
		"name": "mock-repo",
		"packages": {
			"node_modules/axios": {
				"version": "1.0.0"
			},
			"node_modules/suspicious-package": {
				"version": "2.0.0"
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockContent), 0600); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	// Populate cache with mock scan results
	store, err := cache.Load("")
	if err != nil {
		t.Fatalf("failed to load cache: %v", err)
	}

	axiosRes := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "npm",
			Name:      "axios",
			Version:   "1.0.0",
		},
		Decision: types.DecisionAllow,
		Score:    10,
		Reasons: []types.Reason{
			{ID: "trusted_package_reduction", Severity: "informational", Description: "Trusted package", ScoreImpact: -20},
		},
		ScannedAt: time.Now(),
	}
	suspiciousRes := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "npm",
			Name:      "suspicious-package",
			Version:   "2.0.0",
		},
		Decision: types.DecisionBlock,
		Score:    90,
		Reasons: []types.Reason{
			{ID: "credential_canary_read", Severity: "critical", Description: "Attempted to read credential file", ScoreImpact: 100},
		},
		Vulnerabilities: []types.Vulnerability{
			{ID: "CVE-2026-9999", Severity: "critical", Summary: "Remote Code Execution"},
		},
		RegistryInfo: &types.RegistryEvidence{
			Name: "npm-public",
			Type: "public",
			URL:  "https://registry.npmjs.org",
		},
		ScannedAt: time.Now(),
	}

	if err := store.Put(axiosRes); err != nil {
		t.Fatalf("failed to cache axios: %v", err)
	}
	if err := store.Put(suspiciousRes); err != nil {
		t.Fatalf("failed to cache suspicious: %v", err)
	}

	// Setup Policy with Exceptions
	pol := policy.Default()
	pol.PolicyPackName = "enterprise-standard"
	pol.PolicyPackVersion = "2026.06.01"
	pol.PolicyPackOwner = "Platform Engineering"
	pol.PolicyPackSource = "policy-pack"

	// Mock registries config with credentials in URL
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"default": {
				URL:     "https://user:password@registry.npmjs.org/",
				Type:    "public",
				Enabled: true,
			},
		},
	}

	// Mock active & expired exceptions
	pol.Exceptions = []policy.Exception{
		{
			ID:           "EXC-2026-001",
			Ecosystem:    "npm",
			Package:      "suspicious-package",
			VersionRange: ">=2.0.0",
			AllowedUntil: time.Now().Add(240 * time.Hour), // active
			ApprovedBy:   "security@example.com",
			Reason:       "Required by legacy system",
		},
		{
			ID:           "EXC-2026-002",
			Ecosystem:    "npm",
			Package:      "axios",
			VersionRange: ">=1.0.0",
			AllowedUntil: time.Now().Add(-24 * time.Hour), // expired
			ApprovedBy:   "security@example.com",
			Reason:       "Expired test exception",
		},
	}

	// Generate report
	report, err := GenerateReport(tmpDir, pol, true)
	if err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Subtest 1: Verify Report Statistics and Details
	t.Run("Report Generation Metadata", func(t *testing.T) {
		if report.Summary.PackagesScanned != 2 {
			t.Errorf("expected 2 packages scanned, got %d", report.Summary.PackagesScanned)
		}
		if report.Policy.PackName != "enterprise-standard" {
			t.Errorf("expected packName enterprise-standard, got %q", report.Policy.PackName)
		}
	})

	// Subtest 2: Exceptions filtering and validity
	t.Run("Exceptions Filter", func(t *testing.T) {
		activeCount := 0
		expiredCount := 0
		for _, exc := range report.Exceptions {
			if exc.Status == "Active" {
				activeCount++
			} else if exc.Status == "Expired" {
				expiredCount++
			}
		}
		if activeCount != 1 {
			t.Errorf("expected 1 active exception, got %d", activeCount)
		}
		if expiredCount != 1 {
			t.Errorf("expected 1 expired exception, got %d", expiredCount)
		}
	})

	// Subtest 3: Recommendations validation
	t.Run("Recommendations Matching", func(t *testing.T) {
		hasBlockRec := false
		for _, rec := range report.Recommendations {
			if rec.Type == "block" && strings.Contains(rec.Message, "suspicious-package") {
				hasBlockRec = true
			}
		}
		if !hasBlockRec {
			t.Errorf("expected block recommendation for suspicious-package")
		}
	})

	// Subtest 4: Markdown Export
	t.Run("Markdown Exporter", func(t *testing.T) {
		md, err := ExportMarkdown(report)
		if err != nil {
			t.Fatalf("ExportMarkdown failed: %v", err)
		}
		if !strings.Contains(md, "suspicious-package") {
			t.Errorf("markdown does not contain suspicious-package")
		}
		if !strings.Contains(md, "axios") {
			t.Errorf("markdown does not contain axios")
		}
	})

	// Subtest 5: JSON Export Schema
	t.Run("JSON Exporter", func(t *testing.T) {
		js, err := ExportJSON(report)
		if err != nil {
			t.Fatalf("ExportJSON failed: %v", err)
		}
		var parsed RepositoryRiskReport
		if err := json.Unmarshal([]byte(js), &parsed); err != nil {
			t.Fatalf("failed to unmarshal exported JSON: %v", err)
		}
		if parsed.SchemaVersion != "1.0" {
			t.Errorf("expected schema version 1.0, got %q", parsed.SchemaVersion)
		}
	})

	// Subtest 6: HTML Export and no CDN check
	t.Run("HTML Exporter", func(t *testing.T) {
		htmlDoc, err := ExportHTML(report)
		if err != nil {
			t.Fatalf("ExportHTML failed: %v", err)
		}
		if strings.Contains(htmlDoc, "<script src=\"http") || strings.Contains(htmlDoc, "cdn") {
			t.Errorf("HTML contains external CDN references")
		}
		if !strings.Contains(htmlDoc, "suspicious-package") {
			t.Errorf("HTML does not contain suspicious-package")
		}
	})

	// Subtest 7: CSV Exporter
	t.Run("CSV Exporter", func(t *testing.T) {
		csvData, err := ExportCSV(report, "findings")
		if err != nil {
			t.Fatalf("ExportCSV findings failed: %v", err)
		}
		if !strings.Contains(csvData, "suspicious-package,2.0.0,block,90") {
			t.Errorf("CSV findings does not contain expected suspicious-package row, got %q", csvData)
		}
	})

	// Subtest 8: SIEM Export JSONL
	t.Run("SIEM Export", func(t *testing.T) {
		siemData, err := ExportSIEM(report)
		if err != nil {
			t.Fatalf("ExportSIEM failed: %v", err)
		}
		if !strings.Contains(siemData, `"event_type":"package_blocked"`) {
			t.Errorf("SIEM logs do not contain package_blocked event type")
		}
	})

	// Subtest 9: ServiceNow Export
	t.Run("ServiceNow Export", func(t *testing.T) {
		snowData, err := ExportServiceNow(report)
		if err != nil {
			t.Fatalf("ExportServiceNow failed: %v", err)
		}
		if !strings.Contains(snowData, `"tool": "PkgSafe"`) {
			t.Errorf("ServiceNow payload doesn't identify PkgSafe")
		}
	})

	// Subtest 10: Azure DevOps Export
	t.Run("Azure DevOps Export", func(t *testing.T) {
		azData, err := ExportAzureDevOps(report)
		if err != nil {
			t.Fatalf("ExportAzureDevOps failed: %v", err)
		}
		if !strings.Contains(azData, "# PkgSafe Supply Chain Evidence") {
			t.Errorf("Azure DevOps markdown headers are missing")
		}
	})

	// Subtest 11: Evidence Pack ZIP & Manifest
	t.Run("Evidence Pack ZIP", func(t *testing.T) {
		zipPath := filepath.Join(tmpDir, "evidence.zip")
		if err := CreateEvidencePack(zipPath, report, pol); err != nil {
			t.Fatalf("CreateEvidencePack failed: %v", err)
		}

		rZip, err := zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("failed to open generated zip pack: %v", err)
		}
		defer rZip.Close()

		foundManifest := false
		foundPolicy := false
		for _, f := range rZip.File {
			if f.Name == "pkgsafe-evidence-pack/manifest.json" {
				foundManifest = true
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("failed to open manifest inside zip: %v", err)
				}
				b, _ := io.ReadAll(rc)
				rc.Close()

				var manifest Manifest
				if err := json.Unmarshal(b, &manifest); err != nil {
					t.Fatalf("failed to parse manifest: %v", err)
				}
				if manifest.SchemaVersion != "1.0" {
					t.Errorf("expected manifest version 1.0, got %q", manifest.SchemaVersion)
				}
				if len(manifest.Files) == 0 {
					t.Errorf("manifest has 0 files listed")
				}
			}
			if f.Name == "pkgsafe-evidence-pack/raw/policy-effective.json" {
				foundPolicy = true
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("failed to open policy-effective.json inside zip: %v", err)
				}
				b, _ := io.ReadAll(rc)
				rc.Close()

				var loadedPol policy.Policy
				if err := json.Unmarshal(b, &loadedPol); err != nil {
					t.Fatalf("failed to parse policy-effective.json: %v", err)
				}
				urlVal := loadedPol.Registries.Registries["npm"]["default"].URL
				if strings.Contains(urlVal, "password") {
					t.Errorf("expected registry URL to be redacted, but got %q", urlVal)
				}
				if !strings.Contains(urlVal, "[REDACTED]") {
					t.Errorf("expected registry URL to contain [REDACTED], but got %q", urlVal)
				}
			}
		}
		if !foundManifest {
			t.Errorf("manifest.json not found in ZIP pack")
		}
		if !foundPolicy {
			t.Errorf("policy-effective.json not found in ZIP pack")
		}
	})
}
