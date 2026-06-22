package pypi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var DefaultRegistryURL = "https://pypi.org/pypi"

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
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
	if strings.TrimSpace(packageName) == "" {
		return Metadata{}, fmt.Errorf("package name is required")
	}
	endpoint := strings.TrimRight(c.baseURL(), "/") + "/" + url.PathEscape(packageName) + "/json"
	resp, err := c.httpClient().Get(endpoint)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Metadata{}, fmt.Errorf("pypi package %q not found", packageName)
	}
	if resp.StatusCode >= 400 {
		return Metadata{}, fmt.Errorf("pypi registry returned %s", resp.Status)
	}
	var md Metadata
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return Metadata{}, err
	}
	return md, nil
}

func (c Client) DownloadArtifact(artifactURL, cacheDir string) (string, error) {
	if artifactURL == "" {
		return "", fmt.Errorf("missing artifact URL")
	}
	if cacheDir == "" {
		cacheDir = DefaultArtifactCacheDir()
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	cachePath := filepath.Join(cacheDir, artifactCacheName(artifactURL))
	if st, err := os.Stat(cachePath); err == nil && st.Size() > 0 {
		return cachePath, nil
	}
	resp, err := c.httpClient().Get(artifactURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("artifact download returned %s", resp.Status)
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

func DefaultArtifactCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".pkgsafe", "pypi")
	}
	return filepath.Join(home, ".pkgsafe", "pypi")
}

func (c Client) baseURL() string {
	if c.BaseURL == "" {
		return DefaultRegistryURL
	}
	return c.BaseURL
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func artifactCacheName(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	base := "artifact"
	if err == nil && filepath.Base(parsed.Path) != "." {
		base = filepath.Base(parsed.Path)
	}
	sum := sha256.Sum256([]byte(rawURL))
	return base + "-" + hex.EncodeToString(sum[:8])
}
