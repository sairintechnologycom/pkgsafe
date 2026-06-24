package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var DefaultRegistryURL = "https://registry.npmjs.org"

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

type Metadata struct {
	Name     string                     `json:"name"`
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]VersionMetadata `json:"versions"`
	Time     map[string]time.Time       `json:"time"`
}

type VersionMetadata struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Repository  any               `json:"repository"`
	Scripts     map[string]string `json:"scripts"`
	Dist        struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
		Shasum    string `json:"shasum"`
	} `json:"dist"`
	Time time.Time `json:"-"`
}

func FetchMetadata(packageName string) (Metadata, error) {
	return NewClient("").FetchMetadata(packageName)
}

func NewClient(baseURL string) Client {
	if baseURL == "" {
		baseURL = DefaultRegistryURL
	}
	return Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c Client) FetchMetadata(packageName string) (Metadata, error) {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = DefaultRegistryURL
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/" + escapePackage(packageName)
	resp, err := c.httpClient().Get(endpoint)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return Metadata{}, fmt.Errorf("npm registry returned %s", resp.Status)
	}
	var md Metadata
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return Metadata{}, err
	}
	return md, nil
}

func (c Client) DownloadTarball(tarballURL, cacheDir string) (string, error) {
	if tarballURL == "" {
		return "", fmt.Errorf("missing tarball URL")
	}
	if cacheDir == "" {
		cacheDir = DefaultTarballCacheDir()
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	cachePath := filepath.Join(cacheDir, tarballCacheName(tarballURL))
	if st, err := os.Stat(cachePath); err == nil && st.Size() > 0 {
		return cachePath, nil
	}

	resp, err := c.httpClient().Get(tarballURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("tarball download returned %s", resp.Status)
	}

	tmp := cachePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, cachePath); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return cachePath, nil
}

func ResolveVersion(md Metadata, requested string) (VersionMetadata, error) {
	version := requested
	if version == "" || version == "latest" {
		version = md.DistTags["latest"]
	}
	if version == "" {
		return VersionMetadata{}, fmt.Errorf("could not resolve latest version for %s", md.Name)
	}
	vm, ok := md.Versions[version]
	if !ok {
		return VersionMetadata{}, fmt.Errorf("version %s not found for %s", version, md.Name)
	}
	if md.Time != nil {
		vm.Time = md.Time[version]
	}
	return vm, nil
}

func DownloadAndExtractTarball(tarballURL, dest string) error {
	cachePath, err := NewClient("").DownloadTarball(tarballURL, "")
	if err != nil {
		return err
	}
	return ExtractTarball(cachePath, dest)
}

func VerifyTarballIntegrity(tarballPath, integrity, shasum string) error {
	if integrity != "" {
		return verifySRI(tarballPath, integrity)
	}
	if shasum != "" {
		return verifyHexDigest(tarballPath, sha1.New(), shasum)
	}
	return nil
}

const MaxExtractedFiles = 5000
const MaxExtractedBytes = 100 * 1024 * 1024
const MaxSingleFileSize = 50 * 1024 * 1024

func ExtractTarball(tarballPath, dest string) error {
	f, err := os.Open(tarballPath)
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

		// Reject symlinks/hardlinks to prevent link escapes
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return fmt.Errorf("unsafe symlink or hardlink in tarball: %s", header.Name)
		}

		name, ok := cleanTarPath(header.Name)
		if !ok {
			return fmt.Errorf("unsafe file path in tarball: %s", header.Name)
		}
		count++
		if count > MaxExtractedFiles {
			return fmt.Errorf("artifact has too many files")
		}
		target := filepath.Join(dest, name)
		if !isWithinDir(dest, target) {
			return fmt.Errorf("unsafe file path %q escapes destination directory", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if header.Size > MaxSingleFileSize {
				return fmt.Errorf("artifact single file size exceeds limit")
			}
			total += header.Size
			if total > MaxExtractedBytes {
				return fmt.Errorf("artifact extracted size exceeds limit")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, io.LimitReader(tr, header.Size))
			closeErr := f.Close()
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

func LocatePackageJSON(extractedDir string) (string, error) {
	path := filepath.Join(extractedDir, "package", "package.json")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("locate package/package.json: %w", err)
	}
	return path, nil
}

func DefaultTarballCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".pkgsafe", "tarballs")
	}
	return filepath.Join(home, ".pkgsafe", "tarballs")
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func verifySRI(filePath, integrity string) error {
	for _, token := range strings.Fields(integrity) {
		alg, encoded, ok := strings.Cut(token, "-")
		if !ok || encoded == "" {
			continue
		}
		expected, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode integrity digest: %w", err)
		}
		switch alg {
		case "sha512":
			if err := verifyDigest(filePath, sha512.New(), expected); err != nil {
				return err
			}
			return nil
		case "sha384":
			if err := verifyDigest(filePath, sha512.New384(), expected); err != nil {
				return err
			}
			return nil
		case "sha256":
			if err := verifyDigest(filePath, sha256.New(), expected); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("unsupported npm integrity format")
}

func verifyHexDigest(filePath string, h hash.Hash, expectedHex string) error {
	expected, err := hex.DecodeString(strings.TrimSpace(expectedHex))
	if err != nil {
		return fmt.Errorf("decode shasum digest: %w", err)
	}
	return verifyDigest(filePath, h, expected)
}

func verifyDigest(filePath string, h hash.Hash, expected []byte) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), expected) {
		return fmt.Errorf("tarball integrity verification failed")
	}
	return nil
}

func tarballCacheName(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	base := ""
	if err == nil {
		base = filepath.Base(parsed.Path)
	}
	if base == "" || base == "." || base == "/" {
		base = "package.tgz"
	}
	sum := sha256.Sum256([]byte(rawURL))
	return strings.TrimSuffix(base, ".tgz") + "-" + hex.EncodeToString(sum[:8]) + ".tgz"
}

func isWithinDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func cleanTarPath(name string) (string, bool) {
	// Reject paths containing Windows drive letters or alternate data streams
	if strings.Contains(name, ":") {
		return "", false
	}

	name = strings.ReplaceAll(name, "\\", "/")

	// Reject absolute paths
	if strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", false
	}

	// Reject UNC paths or double slashes
	if strings.HasPrefix(name, "//") {
		return "", false
	}

	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", false
		}
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false
	}
	return filepath.FromSlash(clean), true
}

func escapePackage(name string) string {
	if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		return url.PathEscape(name)
	}
	return url.PathEscape(name)
}
