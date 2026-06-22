package pypi

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxExtractedFiles = 5000
const MaxExtractedBytes = 100 * 1024 * 1024

func VerifyArtifactHash(path string, digests map[string]string) error {
	expected := strings.TrimSpace(digests["sha256"])
	if expected == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected) {
		return fmt.Errorf("artifact sha256 verification failed")
	}
	return nil
}

func ExtractArtifact(path, dest string) error {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(name, ".whl") || strings.Contains(name, ".zip"):
		return ExtractZip(path, dest)
	case strings.Contains(name, ".tar.gz") || strings.Contains(name, ".tgz"):
		return ExtractTarGz(path, dest)
	default:
		return fmt.Errorf("unsupported artifact type %q", filepath.Base(path))
	}
}

func ExtractTarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	count := 0
	var total int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name, ok := cleanArchivePath(header.Name)
		if !ok {
			return fmt.Errorf("unsafe archive path %q", header.Name)
		}
		count++
		if count > MaxExtractedFiles {
			return fmt.Errorf("artifact has too many files")
		}
		target := filepath.Join(dest, name)
		if !isWithinDir(dest, target) {
			return fmt.Errorf("archive path escapes destination: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += header.Size
			if total > MaxExtractedBytes {
				return fmt.Errorf("artifact extracted size exceeds limit")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, io.LimitReader(tr, header.Size))
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}

func ExtractZip(path, dest string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > MaxExtractedFiles {
		return fmt.Errorf("artifact has too many files")
	}
	var total int64
	for _, file := range zr.File {
		name, ok := cleanArchivePath(file.Name)
		if !ok {
			return fmt.Errorf("unsafe archive path %q", file.Name)
		}
		target := filepath.Join(dest, name)
		if !isWithinDir(dest, target) {
			return fmt.Errorf("archive path escapes destination: %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(file.UncompressedSize64)
		if total > MaxExtractedBytes {
			return fmt.Errorf("artifact extracted size exceeds limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeOutErr := out.Close()
		closeInErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOutErr != nil {
			return closeOutErr
		}
		if closeInErr != nil {
			return closeInErr
		}
	}
	return nil
}

func cleanArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\x00") {
		return "", false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", false
		}
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || strings.HasPrefix(clean, "..") {
		return "", false
	}
	return clean, true
}

func isWithinDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}
