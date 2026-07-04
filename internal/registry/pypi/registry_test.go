package pypi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
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

// TestExtractZipRejectsOversizeArchive exercises the extraction byte budget
// that guards against decompression bombs, through the same extractZipLimits
// path ExtractZip delegates to (the production budget is now 2 GiB, too big
// to build honestly in a test). It covers the path the extractor itself owns
// (an honestly-declared archive whose contents exceed the budget) as well as
// a forged lying-header bomb, which Go's zip reader additionally refuses to
// inflate past its declared size.
func TestExtractZipRejectsOversizeArchive(t *testing.T) {
	const testBudget = int64(4 * 1024 * 1024)
	chunk := bytes.Repeat([]byte("A"), 1024*1024) // 1 MiB, highly compressible

	overBudget := func(name string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		for written := int64(0); written <= testBudget; written += int64(len(chunk)) {
			if _, err := w.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	// Case 1: honest header, real content over the limit. This is rejected by
	// the extractor's own budget check (declared size is accurate here), so it
	// fails if that check is ever removed.
	t.Run("honest_oversize", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "big.zip")
		if err := os.WriteFile(src, overBudget("big.txt"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := extractZipLimits(src, t.TempDir(), MaxExtractedFiles, testBudget); err == nil {
			t.Fatal("expected oversize archive to be rejected by byte budget")
		}
	})

	// Case 2: forge a classic zip bomb by understating the central-directory
	// UncompressedSize64 so the declared size looks harmless while the deflate
	// stream still inflates past the limit. Go's reader caps inflation at the
	// declared size, so this never reaches the budget check — extraction must
	// still fail, never silently writing past the budget to disk.
	t.Run("forged_lying_header", func(t *testing.T) {
		raw := overBudget("bomb.txt")
		idx := bytes.Index(raw, []byte{0x50, 0x4b, 0x01, 0x02}) // central dir header
		if idx < 0 {
			t.Fatal("central directory header not found")
		}
		binary.LittleEndian.PutUint32(raw[idx+24:idx+28], 10) // understate size
		src := filepath.Join(t.TempDir(), "bomb.zip")
		if err := os.WriteFile(src, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := extractZipLimits(src, t.TempDir(), MaxExtractedFiles, testBudget); err == nil {
			t.Fatal("expected forged zip bomb to be rejected")
		}
	})
}

func TestExtractRejectsTooManyFiles(t *testing.T) {
	t.Run("zip", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for i := 0; i < 5; i++ {
			w, err := zw.Create(fmt.Sprintf("f%d.txt", i))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(t.TempDir(), "many.zip")
		if err := os.WriteFile(src, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := extractZipLimits(src, t.TempDir(), 4, MaxExtractedBytes); err == nil {
			t.Fatal("expected file-count cap rejection")
		}
		if err := extractZipLimits(src, t.TempDir(), 5, MaxExtractedBytes); err != nil {
			t.Fatalf("expected extraction at the cap to succeed, got %v", err)
		}
	})
	t.Run("tar", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "many.tar.gz")
		f, err := os.Create(src)
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		for i := 0; i < 5; i++ {
			if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%d.txt", i), Mode: 0o644, Size: 1}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte("x")); err != nil {
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
		if err := extractTarGzLimits(src, t.TempDir(), 4, MaxExtractedBytes); err == nil {
			t.Fatal("expected file-count cap rejection")
		}
		if err := extractTarGzLimits(src, t.TempDir(), 5, MaxExtractedBytes); err != nil {
			t.Fatalf("expected extraction at the cap to succeed, got %v", err)
		}
	})
}
