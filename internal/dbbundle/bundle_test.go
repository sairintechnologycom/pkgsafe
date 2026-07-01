package dbbundle

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/enterprise"
)

func TestExportVerifyAndImportSignedBundle(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")
	importedPath := filepath.Join(tmp, "imported.db")
	privPath, pub := writeTestKeypair(t, tmp)

	seedTestDB(t, dbPath, time.Now().UTC())

	manifest, err := Export(dbPath, bundlePath, privPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.BundleKind != "offline-intelligence" {
		t.Fatalf("BundleKind = %q, want offline-intelligence", manifest.BundleKind)
	}
	if manifest.VulnerabilityCount != 1 {
		t.Fatalf("VulnerabilityCount = %d, want 1", manifest.VulnerabilityCount)
	}
	if !manifest.Signature.Present {
		t.Fatal("expected signed manifest")
	}

	res, err := Verify(bundlePath, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ChecksumOK || !res.SignaturePresent || !res.SignatureVerified {
		t.Fatalf("unexpected verification result: %+v", res)
	}

	importRes, err := Import(bundlePath, importedPath, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if !importRes.SignatureVerified {
		t.Fatal("expected import to verify signature")
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

func TestVerifyBundleRejectsWrongKey(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")
	privPath, _ := writeTestKeypair(t, tmp)
	_, wrongPubPEM, err := enterprise.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, err := enterprise.ParsePublicKey(wrongPubPEM)
	if err != nil {
		t.Fatal(err)
	}

	seedTestDB(t, dbPath, time.Now().UTC())
	if _, err := Export(dbPath, bundlePath, privPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bundlePath, []ed25519.PublicKey{wrongPub}); err == nil {
		t.Fatal("expected wrong key verification to fail")
	}
}

func TestVerifyBundleDetectsTampering(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")
	tamperedPath := filepath.Join(tmp, "tampered.zip")
	privPath, pub := writeTestKeypair(t, tmp)

	seedTestDB(t, dbPath, time.Now().UTC())
	if _, err := Export(dbPath, bundlePath, privPath); err != nil {
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
	if _, err := Verify(tamperedPath, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected tampered bundle verification to fail")
	}
}

func TestExportBundleReportsStaleFreshness(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "pkgsafe-offline-bundle.zip")

	seedTestDB(t, dbPath, time.Now().UTC().Add(-96*time.Hour))
	manifest, err := Export(dbPath, bundlePath, "")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Freshness["last_update"] != "stale" {
		t.Fatalf("freshness[last_update] = %q, want stale", manifest.Freshness["last_update"])
	}
}

func writeTestKeypair(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	privPEM, pubPEM, err := enterprise.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "bundle.key")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := enterprise.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return privPath, pub
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
