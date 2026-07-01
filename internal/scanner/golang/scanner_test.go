package golang

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/intel/osv"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestScanPackageCached(t *testing.T) {
	// Isolate home/cache
	tempHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

	store, err := cache.Load("")
	if err != nil {
		t.Fatal(err)
	}

	mockRes := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "go", Name: "github.com/foo/bar", Version: "v1.0.0"},
		Decision: types.DecisionAllow,
		Score:    0,
	}
	if err := store.Put(mockRes); err != nil {
		t.Fatal(err)
	}

	scanner := Scanner{
		Policy: policy.Default(),
	}
	res, err := scanner.ScanPackage("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Package.Name != "github.com/foo/bar" || res.Package.Version != "v1.0.0" {
		t.Fatalf("expected cached package to be returned, got %v@%v", res.Package.Name, res.Package.Version)
	}
	if res.Decision != types.DecisionAllow {
		t.Fatalf("expected cached decision to be Allow, got %v", res.Decision)
	}
}

func TestScanPackageOffline(t *testing.T) {
	// Isolate home/cache (so we start empty)
	tempHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

	// Set up blocked package rule
	pol := policy.Default()
	pol.BlockedPackageRules = []policy.BlockedPackageRule{
		{
			Name:     "github.com/bad/module",
			Severity: "critical",
			Reason:   "malicious",
		},
	}

	scanner := Scanner{
		Policy:  pol,
		Offline: true,
	}

	res, err := scanner.ScanPackage("github.com/bad/module", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected blocked package to return DecisionBlock, got %v", res.Decision)
	}
}

func TestScanPackageOnline(t *testing.T) {
	// Isolate home/cache
	tempHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

	// Mock proxy.golang.org server
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Expecting path to match /github.com/foo/bar/@v/v1.0.0.info (or case-encoded)
		if strings.Contains(r.URL.Path, "/github.com/foo/bar/@v/v1.0.0.info") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"Version":"v1.0.0","Time":"2026-06-25T10:00:00Z"}`))
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer proxySrv.Close()

	// Mock OSV server
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"vulns": []}`))
	}))
	defer osvSrv.Close()

	// Reassign osv.NewClient to target the mock server
	oldNewClient := osv.NewClient
	defer func() { osv.NewClient = oldNewClient }()

	osv.NewClient = func() *osv.Client {
		return &osv.Client{
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
			BaseURL:    osvSrv.URL,
		}
	}

	scanner := Scanner{
		BaseURL: proxySrv.URL,
		Policy:  policy.Default(),
	}

	res, err := scanner.ScanPackage("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Package.Name != "github.com/foo/bar" || res.Package.Version != "v1.0.0" {
		t.Fatalf("expected scanned package to be github.com/foo/bar@v1.0.0, got %v@%v", res.Package.Name, res.Package.Version)
	}
}

func TestScanPackageOfflineWithDB(t *testing.T) {
	// Isolate home/cache
	tempHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "pkgsafe.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	vuln := db.Vulnerability{
		ID:          "GHSA-go-1",
		Ecosystem:   "Go",
		PackageName: "github.com/vuln/module",
		Summary:     "Mock Go Vulnerability",
		Severity:    "high",
		AffectedRanges: []db.Range{
			{
				Type: "SEMVER",
				Events: []db.Event{
					{Introduced: "0", Fixed: "1.5.0"},
				},
			},
		},
	}
	if err := d.SaveVulnerabilities(ctx, []db.Vulnerability{vuln}); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveVulnerabilityIndex(ctx, "Go", "github.com/vuln/module", "v1.0.0", "GHSA-go-1"); err != nil {
		t.Fatal(err)
	}
	d.Close()

	scanner := Scanner{
		Policy:  policy.Default(),
		Offline: true,
		DBPath:  dbPath,
	}

	res, err := scanner.ScanPackage("github.com/vuln/module", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(res.Vulnerabilities))
	}
	if res.Vulnerabilities[0].ID != "GHSA-go-1" {
		t.Fatalf("expected vulnerability ID GHSA-go-1, got %s", res.Vulnerabilities[0].ID)
	}
}
