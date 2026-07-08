package cargo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
		Package:  types.PackageIdentity{Ecosystem: "cargo", Name: "serde", Version: "1.0.0"},
		Decision: types.DecisionAllow,
		Score:    0,
	}
	if err := store.Put(mockRes); err != nil {
		t.Fatal(err)
	}

	scanner := Scanner{
		Policy: policy.Default(),
	}
	res, err := scanner.ScanPackage("serde", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Package.Name != "serde" || res.Package.Version != "1.0.0" {
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
			Name:     "malicious-crate",
			Severity: "critical",
			Reason:   "malicious",
		},
	}

	scanner := Scanner{
		Policy:  pol,
		Offline: true,
	}

	res, err := scanner.ScanPackage("malicious-crate", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected blocked package to return DecisionBlock, got %v", res.Decision)
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
		ID:          "GHSA-rust-1",
		Ecosystem:   "crates.io",
		PackageName: "vuln-crate",
		Summary:     "Mock Rust Vulnerability",
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
	if err := d.SaveVulnerabilityIndex(ctx, "crates.io", "vuln-crate", "1.0.0", "GHSA-rust-1"); err != nil {
		t.Fatal(err)
	}
	d.Close()

	scanner := Scanner{
		Policy:  policy.Default(),
		Offline: true,
		DBPath:  dbPath,
	}

	res, err := scanner.ScanPackage("vuln-crate", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(res.Vulnerabilities))
	}
	if res.Vulnerabilities[0].ID != "GHSA-rust-1" {
		t.Fatalf("expected vulnerability ID GHSA-rust-1, got %s", res.Vulnerabilities[0].ID)
	}
}

func TestScanPackageOnline(t *testing.T) {
	// Isolate home/cache
	tempHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

	// Mock crates.io server
	cratesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/crates/serde/1.0.0") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": {"num":"1.0.0","created_at":"2026-06-25T10:00:00Z","yanked":false}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/crates/serde/serde-1.0.0.crate") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(makeMinimalTarGz())
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer cratesSrv.Close()

	// Mock OSV server
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns": []}`))
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
		BaseURL: cratesSrv.URL,
		Policy:  policy.Default(),
	}

	res, err := scanner.ScanPackage("serde", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Package.Name != "serde" || res.Package.Version != "1.0.0" {
		t.Fatalf("expected scanned package to be serde@1.0.0, got %v@%v", res.Package.Name, res.Package.Version)
	}
	if res.Artifact.Yanked {
		t.Fatalf("expected yanked to be false")
	}
}

// TestScanPackageOnlineOSVFailClosed verifies that when the OSV lookup fails,
// the scan does NOT silently score the package as clean: it surfaces a
// vulnerability_data_unavailable reason and does not return an "allow" decision.
func TestScanPackageOnlineOSVFailClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cratesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/crates/serde/1.0.0") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": {"num":"1.0.0","created_at":"2026-06-25T10:00:00Z","yanked":false}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/crates/serde/serde-1.0.0.crate") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(makeMinimalTarGz())
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer cratesSrv.Close()

	// OSV always errors (500) -> lookup cannot complete.
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer osvSrv.Close()

	oldNewClient := osv.NewClient
	defer func() { osv.NewClient = oldNewClient }()
	osv.NewClient = func() *osv.Client {
		return &osv.Client{
			HTTPClient:   &http.Client{Timeout: 5 * time.Second},
			BaseURL:      osvSrv.URL,
			MaxRetries:   1,
			RetryBackoff: time.Millisecond,
		}
	}

	scanner := Scanner{BaseURL: cratesSrv.URL, Policy: policy.Default()}
	res, err := scanner.ScanPackage("serde", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range res.Reasons {
		if r.ID == "vulnerability_data_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected vulnerability_data_unavailable reason on OSV failure, got reasons %+v", res.Reasons)
	}
	if res.Decision == types.DecisionAllow {
		t.Fatalf("expected fail-closed decision (not allow) when OSV unavailable, got %s (score %d)", res.Decision, res.Score)
	}
}

func makeMinimalTarGz() []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	
	content := []byte("[package]\n")
	header := &tar.Header{
		Name:     "serde-1.0.0/Cargo.toml",
		Size:     int64(len(content)),
		Mode:     0644,
		Typeflag: tar.TypeReg,
	}
	_ = tw.WriteHeader(header)
	_, _ = tw.Write(content)
	
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}
