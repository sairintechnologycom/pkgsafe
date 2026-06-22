package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/output"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	rnpm "github.com/niyam-ai/pkgsafe/internal/registry/npm"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestScanPackageResolvesLatestAndScansTarball(t *testing.T) {
	srv := registryServer(t, map[string]string{
		"1.0.0": packageJSON(t, "safe-package"),
		"2.0.0": packageJSON(t, "postinstall-curl"),
	}, "2.0.0")
	defer srv.Close()

	res, err := Scanner{
		Registry: rnpm.NewClient(srv.URL),
		Policy:   policy.Default(),
		CacheDir: t.TempDir(),
	}.ScanPackage("fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Package.Version != "2.0.0" {
		t.Fatalf("expected latest version 2.0.0, got %q", res.Package.Version)
	}
	if !contains(res.Lifecycle, "postinstall") {
		t.Fatalf("expected postinstall lifecycle detection, got %v", res.Lifecycle)
	}
	if res.Decision == types.DecisionAllow {
		t.Fatalf("expected warn/block decision, got allow")
	}
}

func TestScanPackageUsesRequestedVersion(t *testing.T) {
	srv := registryServer(t, map[string]string{
		"1.0.0": packageJSON(t, "safe-package"),
		"2.0.0": packageJSON(t, "postinstall-curl"),
	}, "2.0.0")
	defer srv.Close()

	res, err := Scanner{
		Registry: rnpm.NewClient(srv.URL),
		Policy:   policy.Default(),
		CacheDir: t.TempDir(),
	}.ScanPackage("fixture", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Package.Version != "1.0.0" {
		t.Fatalf("expected requested version 1.0.0, got %q", res.Package.Version)
	}
	if res.Decision != types.DecisionAllow {
		t.Fatalf("expected safe fixture to allow, got %s: %+v", res.Decision, res.Reasons)
	}
}

func TestScanPackageBlocksCredentialPathReference(t *testing.T) {
	srv := registryServer(t, map[string]string{
		"1.0.0": packageJSON(t, "reads-credentials"),
	}, "1.0.0")
	defer srv.Close()

	res, err := Scanner{
		Registry: rnpm.NewClient(srv.URL),
		Policy:   policy.Default(),
		CacheDir: t.TempDir(),
	}.ScanPackage("fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected block, got %s score=%d reasons=%v", res.Decision, res.Score, res.Reasons)
	}
	if !contains(res.Suspicious, ".aws") {
		t.Fatalf("expected .aws suspicious pattern, got %v", res.Suspicious)
	}
}

func TestJSONOutputIncludesRequiredFields(t *testing.T) {
	srv := registryServer(t, map[string]string{
		"1.0.0": packageJSON(t, "postinstall-curl"),
	}, "1.0.0")
	defer srv.Close()

	res, err := Scanner{
		Registry: rnpm.NewClient(srv.URL),
		Policy:   policy.Default(),
		CacheDir: t.TempDir(),
	}.ScanPackage("fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := output.Write(&buf, res, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Ecosystem  string           `json:"ecosystem"`
		Package    string           `json:"package"`
		Version    string           `json:"version"`
		Mode       string           `json:"mode"`
		Score      int              `json:"risk_score"`
		Decision   types.Decision   `json:"decision"`
		Thresholds types.Thresholds `json:"thresholds"`
		Reasons    []types.Reason   `json:"reasons"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Package == "" || got.Version == "" || got.Ecosystem != "npm" || got.Mode == "" {
		t.Fatalf("missing package fields in JSON: %s", buf.String())
	}
	if got.Score == 0 || got.Decision == "" || len(got.Reasons) == 0 || got.Thresholds.BlockMinScore == 0 {
		t.Fatalf("missing scan fields in JSON: %s", buf.String())
	}
	if got.Reasons[0].ID == "" || got.Reasons[0].Severity == "" || got.Reasons[0].Description == "" {
		t.Fatalf("missing reason fields in JSON: %s", buf.String())
	}
}

func registryServer(t *testing.T, versions map[string]string, latest string) *httptest.Server {
	t.Helper()
	tarballs := map[string][]byte{}
	for version, pkgJSON := range versions {
		tarballs["/tarballs/fixture-"+version+".tgz"] = makeTarball(t, map[string]string{
			"package/package.json": pkgJSON,
		})
	}

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/fixture", func(w http.ResponseWriter, r *http.Request) {
		type dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		}
		type versionMetadata struct {
			Name    string            `json:"name"`
			Version string            `json:"version"`
			Scripts map[string]string `json:"scripts,omitempty"`
			Dist    dist              `json:"dist"`
		}
		body := struct {
			Name     string                     `json:"name"`
			DistTags map[string]string          `json:"dist-tags"`
			Versions map[string]versionMetadata `json:"versions"`
		}{
			Name:     "fixture",
			DistTags: map[string]string{"latest": latest},
			Versions: map[string]versionMetadata{},
		}
		for version := range versions {
			tarball := tarballs["/tarballs/fixture-"+version+".tgz"]
			sum := sha512.Sum512(tarball)
			body.Versions[version] = versionMetadata{
				Name:    "fixture",
				Version: version,
				Dist: dist{
					Tarball:   srv.URL + "/tarballs/fixture-" + version + ".tgz",
					Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
				},
			}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/tarballs/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := tarballs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	srv = httptest.NewServer(mux)
	return srv
}

func packageJSON(t *testing.T, fixture string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "npm", fixture, "package.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}

func TestOfflineScanMissingCache(t *testing.T) {
	scanner := Scanner{
		Policy:  policy.Default(),
		Offline: true,
		DBPath:  filepath.Join(t.TempDir(), "pkgsafe.db"),
	}
	_, err := scanner.ScanPackage("axios", "1.6.0")
	if err == nil {
		t.Fatal("expected offline scan to fail when cache is missing")
	}
	if !strings.Contains(err.Error(), "offline scan failed") {
		t.Errorf("expected offline scan failed message, got: %v", err)
	}
}

func TestOfflineScanUsesCachedDataAndDB(t *testing.T) {
	// Setup a clean temp home for caching
	tempHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

	store, err := cache.Load("")
	if err != nil {
		t.Fatal(err)
	}
	mockRes := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "npm", Name: "axios", Version: "1.6.0"},
		Decision: types.DecisionAllow,
	}
	_ = store.Put(mockRes)

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "pkgsafe.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	vuln := db.Vulnerability{
		ID:          "GHSA-axios-1",
		Ecosystem:   "npm",
		PackageName: "axios",
		Summary:     "Mock Axios Vulnerability",
		Severity:    "high",
		AffectedRanges: []db.Range{
			{
				Type: "SEMVER",
				Events: []db.Event{
					{Introduced: "0", Fixed: "1.7.0"},
				},
			},
		},
		FixedVersions: []string{"1.7.0"},
		Source:        "OSV",
		FetchedAt:     time.Now(),
	}
	_ = d.SaveVulnerabilities(ctx, []db.Vulnerability{vuln})
	d.Close()

	scanner := Scanner{
		Policy:  policy.Default(),
		Offline: true,
		DBPath:  dbPath,
	}

	res, err := scanner.ScanPackage("axios", "1.6.0")
	if err != nil {
		t.Fatal(err)
	}

	if res.Decision != types.DecisionWarn {
		t.Errorf("expected decision to be warn due to high severity vulnerability, got: %s", res.Decision)
	}

	if len(res.Vulnerabilities) != 1 || res.Vulnerabilities[0].ID != "GHSA-axios-1" {
		t.Errorf("expected cached vulnerability in scan result, got: %+v", res.Vulnerabilities)
	}
}
