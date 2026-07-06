package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllEcosystems(t *testing.T) {
	got := AllEcosystems()
	want := map[string]bool{"npm": true, "PyPI": true, "Go": true, "crates.io": true}
	if len(got) != len(want) {
		t.Fatalf("AllEcosystems() = %v, want the 4 synced buckets", got)
	}
	for _, e := range got {
		if !want[e] {
			t.Errorf("unexpected ecosystem %q in AllEcosystems()", e)
		}
	}
}

func TestBulkBaseURLDefaultAndOverride(t *testing.T) {
	// Unset → public default.
	t.Setenv(BulkBaseURLEnv, "")
	if got := bulkBaseURL(); got != DefaultBulkBaseURL {
		t.Errorf("bulkBaseURL() default = %q, want %q", got, DefaultBulkBaseURL)
	}

	// Override with a trailing slash → trimmed.
	t.Setenv(BulkBaseURLEnv, "https://mirror.example.com/osv/")
	if got := bulkBaseURL(); got != "https://mirror.example.com/osv" {
		t.Errorf("bulkBaseURL() override = %q, want trailing slash trimmed", got)
	}
}

// TestFetchBulkSuccess drives the full download+parse path against a mock OSV
// bucket, asserting the request path shape and that advisories round-trip.
func TestFetchBulkSuccess(t *testing.T) {
	zipBytes := makeZip(t, map[string]string{
		"GHSA-1.json": `{"id":"GHSA-1","summary":"one"}`,
		"GHSA-2.json": `{"id":"GHSA-2","summary":"two"}`,
	})

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()
	t.Setenv(BulkBaseURLEnv, srv.URL)

	vulns, err := FetchBulk(context.Background(), "npm")
	if err != nil {
		t.Fatalf("FetchBulk: %v", err)
	}
	if gotPath != "/npm/all.zip" {
		t.Errorf("requested path = %q, want /npm/all.zip", gotPath)
	}
	if len(vulns) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(vulns))
	}
}

// TestFetchBulkNon200 verifies a non-OK status is surfaced as an error rather
// than treated as an empty (fail-open) archive.
func TestFetchBulkNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv(BulkBaseURLEnv, srv.URL)

	_, err := FetchBulk(context.Background(), "PyPI")
	if err == nil {
		t.Fatal("expected error on 404 bulk download")
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Errorf("error should mention the status, got %v", err)
	}
}

func TestParseBulkZipRejectsNonZip(t *testing.T) {
	if _, err := ParseBulkZip([]byte("this is not a zip archive")); err == nil {
		t.Fatal("expected error for non-zip input")
	}
}

// TestParseBulkZipSkipsOversizeEntry confirms an advisory entry larger than the
// per-entry cap is skipped without aborting the whole import.
func TestParseBulkZipSkipsOversizeEntry(t *testing.T) {
	huge := `{"id":"GHSA-huge","summary":"` + strings.Repeat("a", maxEntryBytes+16) + `"}`
	zipBytes := makeZip(t, map[string]string{
		"GHSA-ok.json":   `{"id":"GHSA-ok"}`,
		"GHSA-huge.json": huge,
	})

	recs, err := ParseBulkZip(zipBytes)
	if err != nil {
		t.Fatalf("ParseBulkZip: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != "GHSA-ok" {
		t.Fatalf("expected only the small advisory to survive, got %+v", recs)
	}
}
