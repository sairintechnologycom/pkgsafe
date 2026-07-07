package dbbundle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/db"
	versionpkg "github.com/sairintechnologycom/pkgsafe/internal/version"
)

const (
	ManifestPath  = "manifest.json"
	DBPathInZip   = "db/pkgsafe.db"
	ChecksumsPath = "checksums.txt"
	SignaturePath = "signature.sig"

	// SchemaVersion is the manifest schema this build reads and writes.
	SchemaVersion = "1.0"
	// BundleKind identifies offline intelligence bundles.
	BundleKind = "offline-intelligence"

	// MaxBundleFiles and MaxBundleBytes bound what readZip will load into
	// memory. A bundle legitimately holds a handful of files; the database
	// dominates its size.
	MaxBundleFiles = 16
	MaxBundleBytes = 1 << 30 // 1 GiB

	// StaleAfter is how old an advisory sync may be before the bundle (or
	// local database) is reported stale.
	StaleAfter = 72 * time.Hour
)

// sqliteHeader is the magic prefix of every SQLite 3 database file.
var sqliteHeader = []byte("SQLite format 3\x00")

// LastUpdateKeys are the metadata keys that record advisory sync times,
// overall and per ecosystem.
var LastUpdateKeys = []string{"last_update", "last_update_npm", "last_update_pypi", "last_update_go", "last_update_cargo"}

var zipTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

type Manifest struct {
	SchemaVersion       string            `json:"schema_version"`
	BundleKind          string            `json:"bundle_kind"`
	GeneratedAt         string            `json:"generated_at"`
	Tool                string            `json:"tool"`
	PkgSafeVersion      string            `json:"pkgsafe_version"`
	Source              string            `json:"source"`
	DBPath              string            `json:"db_path"`
	DBSHA256            string            `json:"db_sha256"`
	VulnerabilityCount  int               `json:"vulnerability_count"`
	IndexedPackageCount int               `json:"indexed_package_count"`
	EcosystemCounts     map[string]int    `json:"ecosystem_counts"`
	LastUpdates         map[string]string `json:"last_updates"`
	Freshness           map[string]string `json:"freshness"`
	Signature           SignatureInfo     `json:"signature"`
}

type SignatureInfo struct {
	Algorithm string `json:"algorithm,omitempty"`
	Present   bool   `json:"present"`
}

type VerifyResult struct {
	Manifest          Manifest `json:"manifest"`
	ChecksumOK        bool     `json:"checksum_ok"`
	SignaturePresent  bool     `json:"signature_present"`
	SignatureVerified bool     `json:"signature_verified"`
	SignatureChecked  bool     `json:"signature_checked"`
	// FreshnessAtVerify re-evaluates the manifest's last-update timestamps
	// at verification time. The manifest's own freshness map is export-time
	// truth: a bundle exported fresh two weeks ago is stale today.
	FreshnessAtVerify map[string]string `json:"freshness_at_verify,omitempty"`
	// Stale is true when every recorded last-update timestamp is stale or
	// unparseable at verification time.
	Stale bool `json:"stale"`
}

func Export(dbPath, outputPath string) (Manifest, error) {
	if outputPath == "" {
		return Manifest{}, fmt.Errorf("output path is required")
	}
	if dbPath == "" {
		dbPath = db.DefaultDBPath()
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("open database: %w", err)
	}
	manifest, err := buildManifest(d)
	closeErr := d.Close()
	if err != nil {
		return Manifest{}, err
	}
	if closeErr != nil {
		return Manifest{}, closeErr
	}
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("read database: %w", err)
	}
	sum := sha256.Sum256(dbBytes)
	manifest.DBPath = DBPathInZip
	manifest.DBSHA256 = hex.EncodeToString(sum[:])
	manifest.Signature = SignatureInfo{Present: false}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	files := map[string][]byte{
		ManifestPath: manifestBytes,
		DBPathInZip:  dbBytes,
	}
	checksums := checksumsFor(files)
	files[ChecksumsPath] = checksums
	if err := writeZip(outputPath, files); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// SignatureVerifier, when set by a downstream distribution (the private
// pkgsafe-enterprise binary), verifies a signed bundle's detached signature.
// It receives the bundle's files (keyed by in-zip path, including
// SignaturePath) and the parsed manifest, and returns whether the signature is
// valid. The OSS build leaves it nil, so a bundle carrying a signature remains
// private-enterprise functionality and is rejected with the historical error —
// making this seam byte-identical for the public binary.
//
// Note the deliberate asymmetry with license entitlement: a data bundle that
// DECLARES a signature but fails verification is rejected (fail-closed),
// because importing a tampered intelligence database is a security risk.
// Fail-open governs entitlement (never block scanning); it does not govern
// signed-data integrity.
var SignatureVerifier func(files map[string][]byte, manifest Manifest) (bool, error)

func Verify(bundlePath string) (VerifyResult, error) {
	files, err := readZip(bundlePath)
	if err != nil {
		return VerifyResult{}, err
	}
	manifestBytes, ok := files[ManifestPath]
	if !ok {
		return VerifyResult{}, fmt.Errorf("bundle missing %s", ManifestPath)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return VerifyResult{}, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.BundleKind != BundleKind {
		return VerifyResult{Manifest: manifest}, fmt.Errorf("unexpected bundle kind %q (want %q)", manifest.BundleKind, BundleKind)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return VerifyResult{Manifest: manifest}, fmt.Errorf("unsupported bundle schema version %q (this build reads %q)", manifest.SchemaVersion, SchemaVersion)
	}
	expectedChecksums, ok := files[ChecksumsPath]
	if !ok {
		return VerifyResult{}, fmt.Errorf("bundle missing %s", ChecksumsPath)
	}
	verifyFiles := map[string][]byte{}
	for name, content := range files {
		if name == ChecksumsPath || name == SignaturePath {
			continue
		}
		verifyFiles[name] = content
	}
	actualChecksums := checksumsFor(verifyFiles)
	if !bytes.Equal(bytes.TrimSpace(expectedChecksums), bytes.TrimSpace(actualChecksums)) {
		return VerifyResult{Manifest: manifest}, fmt.Errorf("bundle checksum verification failed")
	}
	dbBytes, ok := files[DBPathInZip]
	if !ok {
		return VerifyResult{Manifest: manifest, ChecksumOK: true}, fmt.Errorf("bundle missing %s", DBPathInZip)
	}
	dbSum := sha256.Sum256(dbBytes)
	if manifest.DBSHA256 != "" && !strings.EqualFold(manifest.DBSHA256, hex.EncodeToString(dbSum[:])) {
		return VerifyResult{Manifest: manifest, ChecksumOK: true}, fmt.Errorf("database sha256 does not match manifest")
	}
	res := VerifyResult{
		Manifest:         manifest,
		ChecksumOK:       true,
		SignaturePresent: len(files[SignaturePath]) > 0,
	}
	res.FreshnessAtVerify, res.Stale = EvaluateFreshness(manifest.LastUpdates, StaleAfter)
	if res.SignaturePresent {
		if SignatureVerifier == nil {
			// OSS build: signed bundles are private-enterprise functionality.
			// Byte-identical to the pre-seam behavior.
			return res, fmt.Errorf("signed offline intelligence bundles are private-enterprise functionality")
		}
		res.SignatureChecked = true
		ok, err := SignatureVerifier(files, manifest)
		if err != nil {
			return res, fmt.Errorf("verify bundle signature: %w", err)
		}
		res.SignatureVerified = ok
		if !ok {
			// Fail-closed: a declared-but-invalid signature is rejected.
			return res, fmt.Errorf("bundle signature verification failed")
		}
	}
	return res, nil
}

// EvaluateFreshness re-derives fresh/stale/unknown per recorded timestamp
// and reports whether nothing fresh remains.
func EvaluateFreshness(lastUpdates map[string]string, staleAfter time.Duration) (map[string]string, bool) {
	if len(lastUpdates) == 0 {
		return nil, true
	}
	out := map[string]string{}
	anyFresh := false
	for key, raw := range lastUpdates {
		status := freshnessStatus(raw, staleAfter)
		out[key] = status
		if status == "fresh" {
			anyFresh = true
		}
	}
	return out, !anyFresh
}

func Import(bundlePath, dbPath string) (VerifyResult, error) {
	res, err := Verify(bundlePath)
	if err != nil {
		return res, err
	}
	if dbPath == "" {
		dbPath = db.DefaultDBPath()
	}
	files, err := readZip(bundlePath)
	if err != nil {
		return res, err
	}
	if !bytes.HasPrefix(files[DBPathInZip], sqliteHeader) {
		return res, fmt.Errorf("bundle database payload is not a SQLite database")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return res, err
	}
	tmp := dbPath + ".tmp"
	if err := os.WriteFile(tmp, files[DBPathInZip], 0o600); err != nil {
		return res, err
	}
	if err := os.Rename(tmp, dbPath); err != nil {
		_ = os.Remove(tmp)
		return res, err
	}
	return res, nil
}

func buildManifest(d *db.DB) (Manifest, error) {
	ctx := context.Background()
	vulnCount, _ := d.GetVulnerabilityCount(ctx)
	indexedCount, _ := d.GetIndexedPackageCount(ctx)
	counts, err := ecosystemCounts(ctx, d)
	if err != nil {
		return Manifest{}, err
	}
	lastUpdates := map[string]string{}
	freshness := map[string]string{}
	for _, key := range LastUpdateKeys {
		val, err := d.GetMetadata(ctx, key)
		if err == nil {
			lastUpdates[key] = val
			freshness[key] = freshnessStatus(val, StaleAfter)
		}
	}
	return Manifest{
		SchemaVersion:       SchemaVersion,
		BundleKind:          BundleKind,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		Tool:                "pkgsafe",
		PkgSafeVersion:      versionpkg.Version,
		Source:              "local-db",
		VulnerabilityCount:  vulnCount,
		IndexedPackageCount: indexedCount,
		EcosystemCounts:     counts,
		LastUpdates:         lastUpdates,
		Freshness:           freshness,
	}, nil
}

func ecosystemCounts(ctx context.Context, d *db.DB) (map[string]int, error) {
	rows, err := d.QueryContext(ctx, `SELECT ecosystem, COUNT(*) FROM vulnerability_records GROUP BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var ecosystem string
		var count int
		if err := rows.Scan(&ecosystem, &count); err != nil {
			return nil, err
		}
		counts[ecosystem] = count
	}
	return counts, rows.Err()
}

func freshnessStatus(raw string, staleAfter time.Duration) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "unknown"
	}
	if time.Since(t) > staleAfter {
		return "stale"
	}
	return "fresh"
}

func checksumsFor(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return b.Bytes()
}

func writeZip(path string, files map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.Modified = zipTime
		w, err := zw.CreateHeader(h)
		if err != nil {
			zw.Close()
			return err
		}
		if _, err := w.Write(files[name]); err != nil {
			zw.Close()
			return err
		}
	}
	return zw.Close()
}

func readZip(path string) (map[string][]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	if len(zr.File) > MaxBundleFiles {
		return nil, fmt.Errorf("bundle has too many files (%d > %d)", len(zr.File), MaxBundleFiles)
	}
	files := map[string][]byte{}
	var total int64
	for _, file := range zr.File {
		// Fast-fail on honestly-declared oversize entries, then cap the
		// actual bytes read so extraction never trusts the declared size.
		if int64(file.UncompressedSize64) > MaxBundleBytes-total {
			return nil, fmt.Errorf("bundle contents exceed size limit")
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		remaining := MaxBundleBytes - total
		b, readErr := io.ReadAll(io.LimitReader(rc, remaining+1))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		total += int64(len(b))
		if total > MaxBundleBytes {
			return nil, fmt.Errorf("bundle contents exceed size limit")
		}
		files[file.Name] = b
	}
	return files, nil
}
