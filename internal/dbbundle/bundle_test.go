package dbbundle

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/db"
)

func TestExportVerifyAndImportBundle(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")
	importedPath := filepath.Join(tmp, "imported.db")

	seedTestDB(t, dbPath, time.Now().UTC())

	manifest, err := Export(dbPath, bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.BundleKind != "offline-intelligence" {
		t.Fatalf("BundleKind = %q, want offline-intelligence", manifest.BundleKind)
	}
	if manifest.VulnerabilityCount != 1 {
		t.Fatalf("VulnerabilityCount = %d, want 1", manifest.VulnerabilityCount)
	}
	if manifest.Signature.Present {
		t.Fatal("public bundle should not be signed")
	}

	res, err := Verify(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ChecksumOK || res.SignaturePresent || res.SignatureVerified {
		t.Fatalf("unexpected verification result: %+v", res)
	}

	importRes, err := Import(bundlePath, importedPath)
	if err != nil {
		t.Fatal(err)
	}
	if importRes.SignatureVerified {
		t.Fatal("public import should not verify a signature")
	}
	imported, err := db.Open(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	count, err := imported.GetVulnerabilityCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("imported vulnerability count = %d, want 1", count)
	}
}

func TestVerifyBundleDetectsTampering(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")
	tamperedPath := filepath.Join(tmp, "tampered.zip")

	seedTestDB(t, dbPath, time.Now().UTC())
	if _, err := Export(dbPath, bundlePath); err != nil {
		t.Fatal(err)
	}
	files, err := readZip(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	files[ManifestPath] = append(files[ManifestPath], []byte("\n ")...)
	if err := writeZip(tamperedPath, files); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tamperedPath); err == nil {
		t.Fatal("expected tampered bundle verification to fail")
	}
}

func TestExportBundleReportsStaleFreshness(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")

	seedTestDB(t, dbPath, time.Now().UTC().Add(-96*time.Hour))
	manifest, err := Export(dbPath, bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Freshness["last_update"] != "stale" {
		t.Fatalf("freshness[last_update] = %q, want stale", manifest.Freshness["last_update"])
	}
}

func seedTestDB(t *testing.T, path string, lastUpdate time.Time) {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.SaveVulnerabilities(ctx, []db.Vulnerability{{
		ID:          "GHSA-test-0001",
		Ecosystem:   "npm",
		PackageName: "left-pad",
		Version:     "1.0.0",
		Summary:     "test advisory",
		Severity:    "MODERATE",
		Source:      "test",
		FetchedAt:   time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveVulnerabilityIndex(ctx, "npm", "left-pad", "1.0.0", "GHSA-test-0001"); err != nil {
		t.Fatal(err)
	}
	stamp := lastUpdate.UTC().Format(time.RFC3339)
	for _, key := range []string{"last_update", "last_update_npm"} {
		if err := d.SetMetadata(ctx, key, stamp); err != nil {
			t.Fatal(err)
		}
	}
}
