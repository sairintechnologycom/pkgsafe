package dbbundle

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyRejectsWrongKindAndSchema(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "bundle.zip")
	seedTestDB(t, dbPath, time.Now().UTC())
	if _, err := Export(dbPath, bundlePath); err != nil {
		t.Fatal(err)
	}
	files, err := readZip(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(mutate func(m *Manifest)) string {
		var m Manifest
		if err := json.Unmarshal(files[ManifestPath], &m); err != nil {
			t.Fatal(err)
		}
		mutate(&m)
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		mutated := map[string][]byte{ManifestPath: b, DBPathInZip: files[DBPathInZip]}
		mutated[ChecksumsPath] = checksumsFor(map[string][]byte{ManifestPath: b, DBPathInZip: files[DBPathInZip]})
		out := filepath.Join(tmp, "mutated.zip")
		if err := writeZip(out, mutated); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if _, err := Verify(rewrite(func(m *Manifest) { m.BundleKind = "policy-pack" })); err == nil {
		t.Fatal("expected wrong bundle kind to fail verification")
	}
	if _, err := Verify(rewrite(func(m *Manifest) { m.SchemaVersion = "9.9" })); err == nil {
		t.Fatal("expected unsupported schema version to fail verification")
	}
}

func TestImportRejectsNonSQLitePayload(t *testing.T) {
	tmp := t.TempDir()
	manifest := Manifest{SchemaVersion: SchemaVersion, BundleKind: BundleKind}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		ManifestPath: manifestBytes,
		DBPathInZip:  []byte("#!/bin/sh\necho not a database\n"),
	}
	files[ChecksumsPath] = checksumsFor(map[string][]byte{ManifestPath: manifestBytes, DBPathInZip: files[DBPathInZip]})
	bundlePath := filepath.Join(tmp, "evil.zip")
	if err := writeZip(bundlePath, files); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "imported.db")
	if _, err := Import(bundlePath, target); err == nil {
		t.Fatal("expected non-SQLite payload to be rejected")
	}
}

func TestReadZipRejectsTooManyFiles(t *testing.T) {
	tmp := t.TempDir()
	files := map[string][]byte{}
	for i := 0; i < MaxBundleFiles+1; i++ {
		files[fmt.Sprintf("junk-%02d.txt", i)] = []byte("x")
	}
	path := filepath.Join(tmp, "crowded.zip")
	if err := writeZip(path, files); err != nil {
		t.Fatal(err)
	}
	if _, err := readZip(path); err == nil {
		t.Fatal("expected file-count cap to reject bundle")
	}
}

func TestVerifyRecomputesFreshnessAtVerifyTime(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "pkgsafe.db")
	bundlePath := filepath.Join(tmp, "bundle.zip")
	seedTestDB(t, dbPath, time.Now().UTC().Add(-96*time.Hour))
	if _, err := Export(dbPath, bundlePath); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if res.FreshnessAtVerify["last_update"] != "stale" {
		t.Fatalf("expected stale at verify time: %+v", res.FreshnessAtVerify)
	}
	if !res.Stale {
		t.Fatal("expected overall stale=true when nothing is fresh")
	}

	freshDB := filepath.Join(tmp, "fresh.db")
	freshBundle := filepath.Join(tmp, "fresh.zip")
	seedTestDB(t, freshDB, time.Now().UTC())
	if _, err := Export(freshDB, freshBundle); err != nil {
		t.Fatal(err)
	}
	freshRes, err := Verify(freshBundle)
	if err != nil {
		t.Fatal(err)
	}
	if freshRes.Stale || freshRes.FreshnessAtVerify["last_update"] != "fresh" {
		t.Fatalf("expected fresh bundle: %+v", freshRes)
	}
}
