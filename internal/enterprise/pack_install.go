package enterprise

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InstallPolicyPack verifies (with the default trusted keys) and installs a pack.
func InstallPolicyPack(tarGzPath string) error {
	return InstallPolicyPackWithKeys(tarGzPath, DefaultTrustedKeys())
}

// InstallPolicyPackWithKeys verifies a pack against trustedKeys before
// installing it. Installation never proceeds on a verification failure.
func InstallPolicyPackWithKeys(tarGzPath string, trustedKeys []ed25519.PublicKey) error {
	files, err := VerifyPolicyPackWithKeys(tarGzPath, trustedKeys)
	if err != nil {
		return err
	}

	metaBytes, ok := files["metadata.json"]
	if !ok {
		return fmt.Errorf("missing metadata.json")
	}

	meta, err := ParseMetadata(metaBytes)
	if err != nil {
		return err
	}

	// Determine install path
	packsDir := GetPolicyPacksDir()
	installDir := filepath.Join(packsDir, meta.Name, meta.Version)
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return fmt.Errorf("create install directory: %w", err)
	}

	// Write files. Every pack file — including any bundled pkgsafe.db — is
	// written only inside the pack's sandboxed install directory. A pack must
	// never be able to silently replace the active vulnerability database
	// (which would let a pack blind the scanner), so pkgsafe.db is quarantined
	// here, not applied; importing it is a separate, explicit operator action.
	for fname, content := range files {
		if fname == "pkgsafe.db" {
			fmt.Fprintf(os.Stderr, "Note: policy pack %s bundles a pkgsafe.db; it is stored in the pack directory and does NOT replace the active vulnerability database.\n", meta.Name)
		}
		fpath := filepath.Join(installDir, fname)
		rel, err := filepath.Rel(installDir, fpath)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return fmt.Errorf("unsafe file path %q escapes install directory", fname)
		}
		if err := os.WriteFile(fpath, content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fname, err)
		}
	}

	return nil
}

type PackListItem struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Owner     string    `json:"owner"`
	Expired   bool      `json:"expired"`
	ExpiresAt time.Time `json:"expires_at"`
	Path      string    `json:"path"`
}

func ListPolicyPacks() ([]PackListItem, error) {
	packsDir := GetPolicyPacksDir()
	if _, err := os.Stat(packsDir); os.IsNotExist(err) {
		return nil, nil
	}

	var items []PackListItem
	packNames, err := os.ReadDir(packsDir)
	if err != nil {
		return nil, err
	}

	for _, pName := range packNames {
		if !pName.IsDir() {
			continue
		}
		versionsDir := filepath.Join(packsDir, pName.Name())
		versions, err := os.ReadDir(versionsDir)
		if err != nil {
			continue
		}
		for _, ver := range versions {
			if !ver.IsDir() {
				continue
			}
			metaPath := filepath.Join(versionsDir, ver.Name(), "metadata.json")
			if b, err := os.ReadFile(metaPath); err == nil {
				if meta, err := ParseMetadata(b); err == nil {
					items = append(items, PackListItem{
						Name:      meta.Name,
						Version:   meta.Version,
						Owner:     meta.Owner,
						Expired:   meta.IsExpired(),
						ExpiresAt: meta.ExpiresAt,
						Path:      filepath.Dir(metaPath),
					})
				}
			}
		}
	}

	return items, nil
}

func ExportBundle(outputPath string) error {
	// Find latest active policy pack installed, or bundle current workspace policy configs.
	// Let's pack the current .pkgsafe policy configs if present, or search installed.
	srcDir := ".pkgsafe"
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		packs, err := ListPolicyPacks()
		if err == nil && len(packs) > 0 {
			srcDir = packs[0].Path
		} else {
			srcDir = "."
		}
	}

	// Bundle files
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

	// Read policy pack configs
	for _, fname := range candidateFiles {
		fpath := filepath.Join(srcDir, fname)
		if _, err := os.Stat(fpath); err == nil {
			content, err := os.ReadFile(fpath)
			if err == nil {
				filesToPack[fname] = content
			}
		}
	}

	// The active vulnerability database is intentionally NOT bundled into policy
	// packs: a pack must not be able to ship (and thereby replace) the vuln DB.
	// Offline DB distribution is a separate, explicit concern.

	// Compute checksums for all packed files (except checksums.txt itself)
	var checksumsBuf bytes.Buffer
	for fname, content := range filesToPack {
		sum := sha256.Sum256(content)
		checksumsBuf.WriteString(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), fname))
	}
	filesToPack["checksums.txt"] = checksumsBuf.Bytes()

	// Create output directory if needed
	outDir := filepath.Dir(outputPath)
	if outDir != "." && outDir != "" {
		_ = os.MkdirAll(outDir, 0o755)
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
