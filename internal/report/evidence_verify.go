package report

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	evidenceManifestPath  = "pkgsafe-evidence-pack/manifest.json"
	evidenceSignaturePath = "pkgsafe-evidence-pack/signature.sig"
)

// EvidencePackVerifyResult records the integrity state of a generated evidence
// pack. Signed packs require an injected verifier in downstream distributions.
type EvidencePackVerifyResult struct {
	Manifest          Manifest `json:"manifest"`
	ChecksumOK        bool     `json:"checksum_ok"`
	SignaturePresent  bool     `json:"signature_present"`
	SignatureChecked  bool     `json:"signature_checked"`
	SignatureVerified bool     `json:"signature_verified"`
}

// EvidencePackSignatureVerifier is an optional downstream hook used to verify
// a detached signature when a pack carries signature.sig. OSS builds leave it
// nil, preserving the public verification surface while rejecting signed packs
// that cannot be validated.
var EvidencePackSignatureVerifier func(files map[string][]byte, manifest Manifest) (bool, error)

// VerifyEvidencePack validates the evidence pack manifest, file hashes, and
// optional detached signature.
func VerifyEvidencePack(path string) (EvidencePackVerifyResult, error) {
	files, err := readZipFiles(path)
	if err != nil {
		return EvidencePackVerifyResult{}, err
	}

	manifestBytes, ok := files[evidenceManifestPath]
	if !ok {
		return EvidencePackVerifyResult{}, fmt.Errorf("evidence pack missing manifest.json")
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return EvidencePackVerifyResult{}, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.SchemaVersion != "1.0" {
		return EvidencePackVerifyResult{Manifest: manifest}, fmt.Errorf("unsupported manifest schema version %q", manifest.SchemaVersion)
	}

	expected := make(map[string]string, len(manifest.Files))
	for _, file := range manifest.Files {
		expected[file.Path] = file.SHA256
	}

	for name, content := range files {
		if name == evidenceManifestPath || name == evidenceSignaturePath {
			continue
		}
		want, ok := expected[name]
		if !ok {
			return EvidencePackVerifyResult{Manifest: manifest}, fmt.Errorf("unexpected file in evidence pack: %s", name)
		}
		sum := sha256.Sum256(content)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(want, got) {
			return EvidencePackVerifyResult{Manifest: manifest}, fmt.Errorf("evidence pack checksum mismatch for %s", name)
		}
		delete(expected, name)
	}
	if len(expected) > 0 {
		missing := make([]string, 0, len(expected))
		for name := range expected {
			missing = append(missing, name)
		}
		return EvidencePackVerifyResult{Manifest: manifest}, fmt.Errorf("evidence pack missing files: %s", strings.Join(missing, ", "))
	}

	// Validate the dependency-level SBOM if present.
	if sbomBytes, ok := files["pkgsafe-evidence-pack/dependency-sbom.spdx.json"]; ok {
		if err := validateDependencySPDX(sbomBytes); err != nil {
			return EvidencePackVerifyResult{Manifest: manifest, ChecksumOK: true}, fmt.Errorf("dependency sbom invalid: %w", err)
		}
	}

	res := EvidencePackVerifyResult{
		Manifest:         manifest,
		ChecksumOK:       true,
		SignaturePresent: len(files[evidenceSignaturePath]) > 0 || manifest.Signature.Present,
	}
	if res.SignaturePresent {
		if EvidencePackSignatureVerifier == nil {
			return res, fmt.Errorf("signed evidence packs require downstream signature verification support")
		}
		res.SignatureChecked = true
		ok, err := EvidencePackSignatureVerifier(files, manifest)
		if err != nil {
			return res, fmt.Errorf("verify evidence pack signature: %w", err)
		}
		res.SignatureVerified = ok
		if !ok {
			return res, fmt.Errorf("evidence pack signature verification failed")
		}
	}

	return res, nil
}

func readZipFiles(path string) (map[string][]byte, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	files := make(map[string][]byte, len(r.File))
	for _, f := range r.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			return nil, fmt.Errorf("zip path traversal attempt: %s", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		files[f.Name] = body
	}
	return files, nil
}

func validateDependencySPDX(body []byte) error {
	var doc SPDXDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	if doc.SPDXVersion != "SPDX-2.3" {
		return fmt.Errorf("unexpected SPDX version %q", doc.SPDXVersion)
	}
	if doc.SPDXID == "" || doc.Name == "" {
		return fmt.Errorf("missing required SPDX document fields")
	}
	for _, pkg := range doc.Packages {
		if pkg.Name == "" || pkg.SPDXID == "" {
			return fmt.Errorf("package entry missing required fields")
		}
		hasPURL := false
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") && strings.HasPrefix(ref.ReferenceLocator, "pkg:") {
				hasPURL = true
				break
			}
		}
		if !hasPURL {
			return fmt.Errorf("package %s missing purl external ref", pkg.Name)
		}
	}
	return nil
}
