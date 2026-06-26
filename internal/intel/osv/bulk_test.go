package osv

import (
	"archive/zip"
	"bytes"
	"testing"
)

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEcosystemBucket(t *testing.T) {
	cases := map[string]string{
		"npm": "npm", "NPM": "npm",
		"pypi": "PyPI", "PyPI": "PyPI",
		"go": "Go", "golang": "Go", "Go": "Go",
		"cargo": "crates.io", "crates.io": "crates.io",
	}
	for in, want := range cases {
		got, ok := EcosystemBucket(in)
		if !ok || got != want {
			t.Errorf("EcosystemBucket(%q) = %q,%v; want %q,true", in, got, ok, want)
		}
	}
	if _, ok := EcosystemBucket("maven"); ok {
		t.Error("expected unsupported ecosystem to return false")
	}
}

func TestParseBulkZip(t *testing.T) {
	good := `{"id":"GHSA-1","summary":"x","affected":[{"package":{"name":"lodash","ecosystem":"npm"}}]}`
	files := map[string]string{
		"GHSA-1.json":  good,
		"GHSA-2.json":  `{"id":"GHSA-2","affected":[]}`,
		"bad.json":     `{not json`,        // skipped
		"noid.json":    `{"summary":"y"}`,  // skipped (no id)
		"README.txt":   "ignored non-json", // skipped
		"nested/x.json": `{"id":"GHSA-3"}`,
	}
	recs, err := ParseBulkZip(makeZip(t, files))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	if !ids["GHSA-1"] || !ids["GHSA-2"] || !ids["GHSA-3"] {
		t.Fatalf("expected GHSA-1/2/3, got %v", ids)
	}
	if ids[""] || len(recs) != 3 {
		t.Fatalf("expected exactly 3 valid records, got %d: %v", len(recs), ids)
	}
}
