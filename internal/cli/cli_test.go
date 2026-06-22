package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/intel/osv"
)

func TestUpdateDBAndStatus(t *testing.T) {
	// Create mock OSV server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := osv.QueryResponse{
			Vulns: []osv.Vulnerability{
				{
					ID:      "GHSA-mock",
					Summary: "Mock vulnerability",
					Affected: []osv.Affected{
						{
							Package: osv.Package{
								Name:      "lodash",
								Ecosystem: "npm",
							},
							Ranges: []osv.Range{
								{
									Type: "SEMVER",
									Events: []osv.Event{
										{Introduced: "0", Fixed: "4.17.21"},
									},
								},
							},
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Redirect OSV Client to mock server
	oldNewClient := osv.NewClient
	osv.NewClient = func() *osv.Client {
		return &osv.Client{
			HTTPClient: &http.Client{},
			BaseURL:    server.URL,
		}
	}
	defer func() { osv.NewClient = oldNewClient }()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "pkgsafe.db")

	// Run UpdateDB
	err := UpdateDB(dbPath, "npm", "osv")
	if err != nil {
		t.Fatalf("failed to update db: %v", err)
	}

	// Capture output of DBStatus
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = DBStatus(dbPath)
	if err != nil {
		t.Fatalf("failed to get db status: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "PkgSafe Database Status") {
		t.Errorf("expected output to contain title, got: %s", output)
	}
	if !strings.Contains(output, "Known vulnerability records: 1") {
		t.Errorf("expected 1 vulnerability record in status output, got: %s", output)
	}
}
