package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// DefaultBulkBaseURL is the OSV bulk-export bucket. Each ecosystem is
	// published as <base>/<ecosystem>/all.zip containing one JSON file per
	// advisory.
	DefaultBulkBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	// BulkBaseURLEnv overrides the bulk base URL (private mirror / testing).
	BulkBaseURLEnv = "PKGSAFE_OSV_BULK_BASEURL"

	// Safety caps for the downloaded archive and its entries.
	maxBulkZipBytes    = 512 * 1024 * 1024  // compressed download cap
	maxBulkUncompBytes = 2048 * 1024 * 1024 // total uncompressed cap
	maxBulkEntries     = 1_000_000
	maxEntryBytes      = 8 * 1024 * 1024 // per-advisory JSON cap
)

// bulkHTTPClient uses a generous timeout: all.zip archives can be tens of MB.
// Callers still pass a context for cancellation.
var bulkHTTPClient = &http.Client{Timeout: 10 * time.Minute}

// EcosystemBucket maps an internal/CLI ecosystem name to its OSV bucket path.
// The returned name is the case-sensitive OSV ecosystem identifier.
func EcosystemBucket(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "npm", true
	case "pypi":
		return "PyPI", true
	case "go", "golang":
		return "Go", true
	case "cargo", "crates", "crates.io":
		return "crates.io", true
	default:
		return "", false
	}
}

// AllEcosystems returns the OSV buckets PkgSafe syncs.
func AllEcosystems() []string {
	return []string{"npm", "PyPI", "Go", "crates.io"}
}

func bulkBaseURL() string {
	if v := os.Getenv(BulkBaseURLEnv); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultBulkBaseURL
}

// FetchBulk downloads and parses the OSV all.zip for a single bucket (an OSV
// ecosystem identifier such as "npm" or "PyPI"). It returns every advisory
// record in the archive.
func FetchBulk(ctx context.Context, bucket string) ([]Vulnerability, error) {
	data, err := downloadBulk(ctx, bucket)
	if err != nil {
		return nil, err
	}
	return ParseBulkZip(data)
}

func downloadBulk(ctx context.Context, bucket string) ([]byte, error) {
	url := bulkBaseURL() + "/" + bucket + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := bulkHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv bulk download for %s: status %d", bucket, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBulkZipBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read osv bulk archive for %s: %w", bucket, err)
	}
	if len(data) > maxBulkZipBytes {
		return nil, fmt.Errorf("osv bulk archive for %s exceeds %d bytes", bucket, maxBulkZipBytes)
	}
	return data, nil
}

// ParseBulkZip parses an OSV all.zip archive into advisory records. Each entry
// is a single JSON advisory. Oversize or malformed entries are skipped; the
// archive as a whole is bounded against decompression bombs.
func ParseBulkZip(data []byte) ([]Vulnerability, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open osv bulk archive: %w", err)
	}

	var out []Vulnerability
	var totalBytes int64
	entries := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		entries++
		if entries > maxBulkEntries {
			return nil, fmt.Errorf("osv bulk archive has too many entries")
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open archive entry %s: %w", f.Name, err)
		}
		// Cap each entry's decompressed bytes to guard against a zip bomb.
		raw, err := io.ReadAll(io.LimitReader(rc, maxEntryBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read archive entry %s: %w", f.Name, err)
		}
		if len(raw) > maxEntryBytes {
			continue // skip implausibly large advisory entry
		}
		totalBytes += int64(len(raw))
		if totalBytes > maxBulkUncompBytes {
			return nil, fmt.Errorf("osv bulk archive exceeds uncompressed size limit")
		}

		var v Vulnerability
		if err := json.Unmarshal(raw, &v); err != nil || v.ID == "" {
			continue // skip malformed entry rather than abort the whole import
		}
		out = append(out, v)
	}
	return out, nil
}
