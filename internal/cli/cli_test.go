package cli

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildAllZip returns an OSV-style all.zip with one JSON file per advisory.
func buildAllZip(t *testing.T, advisories map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range advisories {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUpdateDBAndStatus(t *testing.T) {
	// One advisory affecting lodash, served as the npm all.zip.
	advisory := `{
		"id": "GHSA-mock",
		"summary": "Mock vulnerability",
		"affected": [{
			"package": {"name": "lodash", "ecosystem": "npm"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
		}]
	}`
	zipBytes := buildAllZip(t, map[string]string{"GHSA-mock.json": advisory})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/all.zip" {
			w.Header().Set("Content-Type", "application/zip")
			w.Write(zipBytes)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("PKGSAFE_OSV_BULK_BASEURL", srv.URL)

	dbPath := filepath.Join(t.TempDir(), "pkgsafe.db")

	if err := UpdateDB(dbPath, "npm", "osv"); err != nil {
		t.Fatalf("failed to update db: %v", err)
	}

	// Capture DBStatus output.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	if err := DBStatus(dbPath); err != nil {
		os.Stdout = oldStdout
		t.Fatalf("failed to get db status: %v", err)
	}
	w.Close()
	os.Stdout = oldStdout

	var out bytes.Buffer
	_, _ = io.Copy(&out, r)
	output := out.String()

	if !strings.Contains(output, "PkgSafe Database Status") {
		t.Errorf("expected output to contain title, got: %s", output)
	}
	if !strings.Contains(output, "Known vulnerability records: 1") {
		t.Errorf("expected 1 vulnerability record in status output, got: %s", output)
	}
}
