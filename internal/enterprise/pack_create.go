package enterprise

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func CreatePolicyPack(name string, srcDir string, outputPath string) error {
	if srcDir == "" {
		srcDir = ".pkgsafe"
	}
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		// fallback to current directory
		srcDir = "."
	}

	// 1. Validate or write metadata.json
	metaPath := filepath.Join(srcDir, "metadata.json")
	var metaBytes []byte
	var err error
	if _, err = os.Stat(metaPath); os.IsNotExist(err) {
		// generate default metadata
		meta := Metadata{
			SchemaVersion: "1.0",
			Name:          name,
			Version:       time.Now().Format("2006.01.02"),
			Description:   "Generated enterprise PkgSafe policy pack",
			Owner:         "Platform Engineering",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().AddDate(0, 6, 0).UTC(),
			Compatibility: Compatibility{MinPkgSafeVersion: "0.1.0"},
			DefaultMode:   "warn",
			Environments:  []string{"developer", "ci", "ai_agent"},
		}
		metaBytes, _ = json.MarshalIndent(meta, "", "  ")
		if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
			return fmt.Errorf("write default metadata: %w", err)
		}
	} else {
		metaBytes, err = os.ReadFile(metaPath)
		if err != nil {
			return err
		}
		// Validate it
		meta, err := ParseMetadata(metaBytes)
		if err != nil {
			return fmt.Errorf("invalid metadata in src dir: %w", err)
		}
		if name != "" && meta.Name != name {
			meta.Name = name
			metaBytes, _ = json.MarshalIndent(meta, "", "  ")
			_ = os.WriteFile(metaPath, metaBytes, 0o644)
		}
	}

	// 2. Gather list of pack files to include
	candidateFiles := []string{
		"metadata.json",
		"policy.yaml",
		"registries.yaml",
		"trusted-packages.yaml",
		"blocked-packages.yaml",
		"exceptions.yaml",
		"scopes.yaml",
	}

	filesToPack := make(map[string][]byte)
	var checksumsLines []string

	for _, fname := range candidateFiles {
		fpath := filepath.Join(srcDir, fname)
		if _, err := os.Stat(fpath); err == nil {
			content, err := os.ReadFile(fpath)
			if err != nil {
				return err
			}
			filesToPack[fname] = content
			h := sha256.New()
			h.Write(content)
			checksumsLines = append(checksumsLines, fmt.Sprintf("%s: %s", fname, hex.EncodeToString(h.Sum(nil))))
		}
	}

	// Write checksums.txt
	checksumsContent := strings.Join(checksumsLines, "\n") + "\n"
	filesToPack["checksums.txt"] = []byte(checksumsContent)

	// Create tarball
	outDir := filepath.Dir(outputPath)
	if outDir != "." && outDir != "" {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
	}

	tf, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer tf.Close()

	gw := gzip.NewWriter(tf)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for fname, content := range filesToPack {
		hdr := &tar.Header{
			Name:    fname,
			Mode:    0o644,
			Size:    int64(len(content)),
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}

	return nil
}
