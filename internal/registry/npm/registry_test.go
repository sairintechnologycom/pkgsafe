package npm

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveVersionUsesLatestDistTag(t *testing.T) {
	md := Metadata{
		Name:     "fixture",
		DistTags: map[string]string{"latest": "2.0.0"},
		Versions: map[string]VersionMetadata{
			"1.0.0": {Name: "fixture", Version: "1.0.0"},
			"2.0.0": {Name: "fixture", Version: "2.0.0"},
		},
	}
	vm, err := ResolveVersion(md, "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Version != "2.0.0" {
		t.Fatalf("expected latest 2.0.0, got %q", vm.Version)
	}
}

func TestDownloadTarballCachesResponse(t *testing.T) {
	tarball := makeTarball(t, map[string]string{
		"package/package.json": `{"name":"fixture","version":"1.0.0"}`,
	})
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	client := NewClient("")
	cacheDir := t.TempDir()
	first, err := client.DownloadTarball(srv.URL+"/fixture-1.0.0.tgz", cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.DownloadTarball(srv.URL+"/fixture-1.0.0.tgz", cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("expected cached path reuse, got %q and %q", first, second)
	}
	if hits != 1 {
		t.Fatalf("expected one tarball download, got %d", hits)
	}
}

func TestExtractTarballPreservesPackageJSONLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	writeTarball(t, path, map[string]string{
		"package/package.json": `{"name":"fixture","version":"1.0.0"}`,
		"package/lib/index.js": `module.exports = true`,
	})
	dest := t.TempDir()
	if err := ExtractTarball(path, dest); err != nil {
		t.Fatal(err)
	}
	pkgJSON, err := LocatePackageJSON(dest)
	if err != nil {
		t.Fatal(err)
	}
	if pkgJSON != filepath.Join(dest, "package", "package.json") {
		t.Fatalf("unexpected package.json path: %s", pkgJSON)
	}
	if _, err := os.Stat(filepath.Join(dest, "package", "lib", "index.js")); err != nil {
		t.Fatalf("expected nested file: %v", err)
	}
}

func TestVerifyTarballIntegrityAcceptsNPMIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	writeTarball(t, path, map[string]string{
		"package/package.json": `{"name":"fixture","version":"1.0.0"}`,
	})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(b)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	if err := VerifyTarballIntegrity(path, integrity, ""); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyTarballIntegrityRejectsMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	writeTarball(t, path, map[string]string{
		"package/package.json": `{"name":"fixture","version":"1.0.0"}`,
	})
	if err := VerifyTarballIntegrity(path, "sha512-"+base64.StdEncoding.EncodeToString([]byte("wrong")), ""); err == nil {
		t.Fatal("expected integrity mismatch")
	}
}

func TestExtractTarballRejectsTraversalEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	writeTarball(t, path, map[string]string{
		"package/package.json": `{"name":"fixture","version":"1.0.0"}`,
		"package/../evil.txt":  `bad`,
	})
	dest := t.TempDir()
	err := ExtractTarball(path, dest)
	if err == nil {
		t.Fatal("expected traversal entry to be rejected with an error")
	}
}

func TestExtractTarballSingleFileSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "too_large_single.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "package/huge_single.bin",
		Mode: 0o644,
		Size: MaxSingleFileSize + 1,
	}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	dest := t.TempDir()
	err = ExtractTarball(path, dest)
	if err == nil {
		t.Fatal("expected failure due to single file size limit")
	}
	if !strings.Contains(err.Error(), "artifact single file size exceeds limit") {
		t.Fatalf("expected single file size limit error, got %v", err)
	}
}

func TestExtractTarballFileLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "too_many_files.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i := 0; i <= MaxExtractedFiles; i++ {
		name := fmt.Sprintf("package/file%d.js", i)
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("a")); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	dest := t.TempDir()
	err = ExtractTarball(path, dest)
	if err == nil {
		t.Fatal("expected failure due to too many files limit")
	}
	if !strings.Contains(err.Error(), "artifact has too many files") {
		t.Fatalf("expected too many files error, got %v", err)
	}
}

func TestExtractTarballSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "too_large.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	// Write three headers, each of 40MB. Collectively they are 120MB, exceeding 100MB total limit,
	// but individually under 50MB single file size limit.
	zeroBuf := make([]byte, 1024*1024) // 1MB buffer
	for i := 0; i < 3; i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("package/huge-%d.bin", i),
			Mode: 0o644,
			Size: 40 * 1024 * 1024,
		}); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 40; j++ {
			if _, err := tw.Write(zeroBuf); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	dest := t.TempDir()
	err = ExtractTarball(path, dest)
	if err == nil {
		t.Fatal("expected failure due to file size limit")
	}
	if !strings.Contains(err.Error(), "artifact extracted size exceeds limit") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	writeTarball(t, path, files)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeTarball(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
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
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
