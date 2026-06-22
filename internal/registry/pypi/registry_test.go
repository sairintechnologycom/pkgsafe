package pypi

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveVersionLatestNonYanked(t *testing.T) {
	md := Metadata{
		Info: Info{Name: "demo"},
		Releases: map[string][]File{
			"1.0.0": {{Filename: "demo-1.0.0.tar.gz", PackageType: "sdist"}},
			"2.0.0": {{Filename: "demo-2.0.0.tar.gz", PackageType: "sdist", Yanked: true}},
		},
	}
	vm, err := ResolveVersion(md, "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Version != "1.0.0" {
		t.Fatalf("expected latest non-yanked 1.0.0, got %s", vm.Version)
	}
}

func TestResolveVersionExactMissing(t *testing.T) {
	_, err := ResolveVersion(Metadata{Info: Info{Name: "demo"}, Releases: map[string][]File{"1.0.0": {{Filename: "x.whl"}}}}, "9.9.9")
	if err == nil {
		t.Fatal("expected missing version error")
	}
}

func TestResolveVersionDetectsWheelAndSource(t *testing.T) {
	vm, err := ResolveVersion(Metadata{Info: Info{Name: "demo"}, Releases: map[string][]File{
		"1.0.0": {
			{Filename: "demo-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel"},
			{Filename: "demo-1.0.0.tar.gz", PackageType: "sdist"},
		},
	}}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(vm.WheelFiles) != 1 || len(vm.SourceFiles) != 1 {
		t.Fatalf("expected wheel and source files, got %+v", vm)
	}
}

func TestExtractTarGzRejectsTraversal(t *testing.T) {
	src := filepath.Join(t.TempDir(), "bad.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.py", Mode: 0o644, Size: int64(len("x"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
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
	if err := ExtractTarGz(src, t.TempDir()); err == nil {
		t.Fatal("expected traversal extraction error")
	}
}
