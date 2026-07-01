package dbbundle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/sairintechnologycom/pkgsafe/internal/enterprise"
	versionpkg "github.com/sairintechnologycom/pkgsafe/internal/version"
)

const (
	ManifestPath  = "manifest.json"
	DBPathInZip   = "db/pkgsafe.db"
	ChecksumsPath = "checksums.txt"
	SignaturePath = "signature.sig"
)

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
}

func Export(dbPath, outputPath, signingKeyPath string) (Manifest, error) {
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
	manifest.Signature = SignatureInfo{Present: signingKeyPath != ""}
	if signingKeyPath != "" {
		manifest.Signature.Algorithm = enterprise.SignatureAlgorithm
	}
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
	if signingKeyPath != "" {
		priv, err := enterprise.LoadPrivateKey(signingKeyPath)
		if err != nil {
			return Manifest{}, err
		}
		files[SignaturePath] = enterprise.SignPack(priv, checksums)
	}
	if err := writeZip(outputPath, files); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Verify(bundlePath string, trustedKeys []ed25519.PublicKey) (VerifyResult, error) {
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
	if res.SignaturePresent && len(trustedKeys) > 0 {
		res.SignatureChecked = true
		if err := enterprise.VerifyPackSignature(trustedKeys, expectedChecksums, files[SignaturePath]); err != nil {
			return res, err
		}
		res.SignatureVerified = true
	}
	return res, nil
}

func Import(bundlePath, dbPath string, trustedKeys []ed25519.PublicKey) (VerifyResult, error) {
	res, err := Verify(bundlePath, trustedKeys)
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
	for _, key := range []string{"last_update", "last_update_npm", "last_update_pypi", "last_update_go", "last_update_cargo"} {
		val, err := d.GetMetadata(ctx, key)
		if err == nil {
			lastUpdates[key] = val
			freshness[key] = freshnessStatus(val, 72*time.Hour)
		}
	}
	return Manifest{
		SchemaVersion:       "1.0",
		BundleKind:          "offline-intelligence",
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
		h.SetModTime(zipTime)
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
	files := map[string][]byte{}
	for _, file := range zr.File {
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		b, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		files[file.Name] = b
	}
	return files, nil
}
