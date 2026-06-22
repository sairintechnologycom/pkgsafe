package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDBLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	// 1. Test initial creation and migration
	d, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open/create test db: %v", err)
	}
	defer d.Close()

	// 2. Test idempotency (open again)
	d2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db second time: %v", err)
	}
	d2.Close()

	ctx := context.Background()

	// 3. Test Metadata operations
	err = d.SetMetadata(ctx, "last_update", "2026-06-22T08:00:00Z")
	if err != nil {
		t.Fatalf("failed to set metadata: %v", err)
	}
	val, err := d.GetMetadata(ctx, "last_update")
	if err != nil {
		t.Fatalf("failed to get metadata: %v", err)
	}
	if val != "2026-06-22T08:00:00Z" {
		t.Errorf("expected last_update to be 2026-06-22T08:00:00Z, got %q", val)
	}

	// 4. Test Vulnerability CRUD
	vuln := Vulnerability{
		ID:          "GHSA-123",
		Ecosystem:   "npm",
		PackageName: "lodash",
		Summary:     "Test vulnerability",
		Severity:    "high",
		Aliases:     []string{"CVE-456"},
		AffectedRanges: []Range{
			{
				Type: "SEMVER",
				Events: []Event{
					{Introduced: "0", Fixed: "4.17.21"},
				},
			},
		},
		FixedVersions: []string{"4.17.21"},
		References:    []string{"https://example.com/advisory"},
		Source:        "OSV",
		FetchedAt:     time.Now(),
	}

	err = d.SaveVulnerabilities(ctx, []Vulnerability{vuln})
	if err != nil {
		t.Fatalf("failed to save vulnerability: %v", err)
	}

	// Fetch vulnerability
	vulns, err := d.GetVulnerabilitiesForPackage(ctx, "npm", "lodash")
	if err != nil {
		t.Fatalf("failed to get vulnerabilities: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "GHSA-123" || len(vulns[0].Aliases) != 1 || vulns[0].Aliases[0] != "CVE-456" {
		t.Errorf("unexpected vulnerability content: %+v", vulns[0])
	}

	// 5. Test Vulnerability indexing
	err = d.SaveVulnerabilityIndex(ctx, "npm", "lodash", "4.17.20", "GHSA-123")
	if err != nil {
		t.Fatalf("failed to save vulnerability index: %v", err)
	}

	indexed, err := d.GetIndexedVulnerabilities(ctx, "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("failed to get indexed vulnerabilities: %v", err)
	}
	if len(indexed) != 1 {
		t.Fatalf("expected 1 indexed vulnerability, got %d", len(indexed))
	}
	if indexed[0].ID != "GHSA-123" {
		t.Errorf("expected indexed vulnerability ID GHSA-123, got %s", indexed[0].ID)
	}

	// Test count functions
	vCount, err := d.GetVulnerabilityCount(ctx)
	if err != nil {
		t.Fatalf("failed to get vulnerability count: %v", err)
	}
	if vCount != 1 {
		t.Errorf("expected vuln count 1, got %d", vCount)
	}

	pCount, err := d.GetIndexedPackageCount(ctx)
	if err != nil {
		t.Fatalf("failed to get indexed package count: %v", err)
	}
	if pCount != 1 {
		t.Errorf("expected indexed package count 1, got %d", pCount)
	}
}
