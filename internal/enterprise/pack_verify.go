package enterprise

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"gopkg.in/yaml.v3"
)

type PackValidationError struct {
	Code int
	Err  error
}

func (e PackValidationError) Error() string {
	return e.Err.Error()
}

// VerifyPolicyPack verifies a policy pack using the default trusted keys
// (PKGSAFE_PACK_PUBLIC_KEYS and ~/.pkgsafe/trusted-keys). See
// VerifyPolicyPackWithKeys for the signature-trust semantics.
func VerifyPolicyPack(tarGzPath string) (map[string][]byte, error) {
	return VerifyPolicyPackWithKeys(tarGzPath, DefaultTrustedKeys())
}

// VerifyPolicyPackWithKeys verifies a policy pack's structure, checksums, and
// (when applicable) its cryptographic signature against trustedKeys.
//
// Signature semantics:
//   - If metadata.signing.required is true, the pack MUST carry a signature.sig
//     that verifies against one of trustedKeys; if trustedKeys is empty or the
//     signature is missing/invalid, verification FAILS CLOSED.
//   - If a signature is present but signing is not required, it is still
//     verified when trusted keys are configured (a tampered/forged signature
//     fails); with no trusted keys configured it is skipped with a warning.
//   - Unsigned packs that do not require signing verify as before.
func VerifyPolicyPackWithKeys(tarGzPath string, trustedKeys []ed25519.PublicKey) (map[string][]byte, error) {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return nil, PackValidationError{Code: 2, Err: fmt.Errorf("open pack file: %w", err)}
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, PackValidationError{Code: 2, Err: fmt.Errorf("gzip reader: %w", err)}
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	files := make(map[string][]byte)
	var totalSize int64
	const MaxPackExtractedBytes = 50 * 1024 * 1024 // 50 MB limit
	const MaxPackFileCount = 1000

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, PackValidationError{Code: 2, Err: fmt.Errorf("read tar: %w", err)}
		}

		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("unsafe symlink or hardlink in policy pack: %s", hdr.Name)}
		}

		if hdr.Typeflag == tar.TypeReg {
			cleanName, ok := cleanPackPath(hdr.Name)
			if !ok {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("unsafe file path in policy pack: %s", hdr.Name)}
			}
			if len(files) >= MaxPackFileCount {
				return nil, PackValidationError{Code: 2, Err: fmt.Errorf("policy pack has too many files")}
			}
			totalSize += hdr.Size
			if totalSize > MaxPackExtractedBytes {
				return nil, PackValidationError{Code: 2, Err: fmt.Errorf("policy pack extracted size exceeds limit")}
			}
			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, io.LimitReader(tr, hdr.Size)); err != nil {
				return nil, PackValidationError{Code: 2, Err: fmt.Errorf("read tar entry %s: %w", hdr.Name, err)}
			}
			files[cleanName] = buf.Bytes()
		}
	}

	// 1. Verify Checksums
	checksumsContent, ok := files["checksums.txt"]
	if !ok {
		return nil, PackValidationError{Code: 3, Err: fmt.Errorf("missing checksums.txt in pack")}
	}
	if err := VerifyChecksums(files, string(checksumsContent)); err != nil {
		return nil, PackValidationError{Code: 3, Err: fmt.Errorf("checksum verification failed: %w", err)}
	}

	// 2. Parse and Validate metadata.json
	metaBytes, ok := files["metadata.json"]
	if !ok {
		return nil, PackValidationError{Code: 1, Err: fmt.Errorf("missing metadata.json in pack")}
	}
	meta, err := ParseMetadata(metaBytes)
	if err != nil {
		return nil, PackValidationError{Code: 1, Err: err}
	}
	if err := ValidateMetadata(meta); err != nil {
		return nil, PackValidationError{Code: 1, Err: err}
	}

	// Cryptographically verify the pack signature. The signature is computed
	// over checksums.txt, which in turn covers every other file by SHA-256, so
	// a valid signature authenticates the whole pack.
	sig, hasSig := files["signature.sig"]
	if meta.Signing.Required && !hasSig {
		return nil, PackValidationError{Code: 3, Err: fmt.Errorf("signature.sig is required by metadata but missing")}
	}
	if meta.Signing.Algorithm != "" && meta.Signing.Algorithm != SignatureAlgorithm {
		return nil, PackValidationError{Code: 1, Err: fmt.Errorf("unsupported signing algorithm %q (only %q is supported)", meta.Signing.Algorithm, SignatureAlgorithm)}
	}
	if hasSig {
		switch {
		case len(trustedKeys) > 0:
			if err := VerifyPackSignature(trustedKeys, checksumsContent, sig); err != nil {
				return nil, PackValidationError{Code: 3, Err: fmt.Errorf("signature verification failed: %w", err)}
			}
		case meta.Signing.Required:
			// Required but nothing to verify against — fail closed.
			return nil, PackValidationError{Code: 3, Err: fmt.Errorf("pack requires a signature but no trusted public key is configured (set %s or add keys to %s)", TrustedKeysEnv, TrustedKeysDir())}
		default:
			fmt.Fprintf(os.Stderr, "Warning: policy pack %s carries a signature but no trusted public key is configured; signature not verified\n", meta.Name)
		}
	}

	// Warn if expired
	if meta.IsExpired() {
		fmt.Fprintf(os.Stderr, "Warning: policy pack %s is expired (expired at %s)\n", meta.Name, meta.ExpiresAt.Format(time.RFC3339))
	}

	// 3. Validate policy.yaml if present
	if polBytes, present := files["policy.yaml"]; present {
		// Use standard yaml to check syntax first
		var rawMap map[string]interface{}
		if err := yaml.Unmarshal(polBytes, &rawMap); err != nil {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid policy.yaml YAML syntax: %w", err)}
		}

		// Let's create a temporary file to call policy.Load
		tmpFile, err := os.CreateTemp("", "policy-*.yaml")
		if err != nil {
			return nil, PackValidationError{Code: 2, Err: err}
		}
		defer os.Remove(tmpFile.Name())
		_, _ = tmpFile.Write(polBytes)
		_ = tmpFile.Close()

		loadedPol, err := policy.Load(tmpFile.Name())
		if err != nil {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("policy validation failed: %w", err)}
		}

		// Check unknown rule IDs and invalid severity/score
		defaultPol := policy.Default()
		for id, rule := range loadedPol.Rules {
			if _, exists := defaultPol.Rules[id]; !exists {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("unknown rule ID: %s", id)}
			}
			if rule.Severity != "low" && rule.Severity != "medium" && rule.Severity != "high" && rule.Severity != "critical" && rule.Severity != "informational" {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid severity for rule %s: %s", id, rule.Severity)}
			}
			if rule.Score < -100 || rule.Score > 100 {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid score for rule %s: %d", id, rule.Score)}
			}
		}
	}

	// 4. Validate registries.yaml
	var regMap map[string]map[string]interface{}
	if regBytes, present := files["registries.yaml"]; present {
		if err := yaml.Unmarshal(regBytes, &regMap); err != nil {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid registries.yaml YAML syntax: %w", err)}
		}
		// Validate registry URLs
		registriesVal, exists := regMap["registries"]
		if exists {
			for ecoName, ecoRegs := range registriesVal {
				ecoRegsMap, ok := ecoRegs.(map[string]interface{})
				if !ok {
					continue
				}
				for regName, regVal := range ecoRegsMap {
					regData, ok := regVal.(map[string]interface{})
					if !ok {
						continue
					}
					urlVal, ok := regData["url"].(string)
					if ok {
						if urlVal == "" {
							return nil, PackValidationError{Code: 1, Err: fmt.Errorf("registry %s/%s url cannot be empty", ecoName, regName)}
						}
						u, err := url.Parse(urlVal)
						if err != nil || u.Scheme == "" || u.Host == "" {
							return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid registry URL %q for %s/%s", urlVal, ecoName, regName)}
						}
					}
				}
			}
		}
	}

	// 5. Validate trusted-packages.yaml and blocked-packages.yaml
	var trustedConfig TrustedPackagesConfig
	var blockedConfig BlockedPackagesConfig
	trustedMap := make(map[string]bool)
	blockedMap := make(map[string]bool)

	if tBytes, present := files["trusted-packages.yaml"]; present {
		if err := yaml.Unmarshal(tBytes, &trustedConfig); err != nil {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid trusted-packages.yaml YAML syntax: %w", err)}
		}
		for eco, rules := range trustedConfig.TrustedPackages {
			for _, rule := range rules {
				if rule.Name == "" {
					return nil, PackValidationError{Code: 1, Err: fmt.Errorf("trusted package name cannot be empty in %s", eco)}
				}
				key := eco + ":" + rule.Name + ":" + rule.VersionRange
				trustedMap[key] = true
			}
		}
	}

	if bBytes, present := files["blocked-packages.yaml"]; present {
		if err := yaml.Unmarshal(bBytes, &blockedConfig); err != nil {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid blocked-packages.yaml YAML syntax: %w", err)}
		}
		for eco, rules := range blockedConfig.BlockedPackages {
			for _, rule := range rules {
				if rule.Name == "" {
					return nil, PackValidationError{Code: 1, Err: fmt.Errorf("blocked package name cannot be empty in %s", eco)}
				}
				key := eco + ":" + rule.Name + ":" + rule.VersionRange
				blockedMap[key] = true
				if rule.Reason == "" {
					return nil, PackValidationError{Code: 1, Err: fmt.Errorf("blocked package %s in %s must include a reason", rule.Name, eco)}
				}
				// check expired block entries warning
				if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
					fmt.Fprintf(os.Stderr, "Warning: blocked package entry %s in %s has expired\n", rule.Name, eco)
				}
			}
		}
	}

	// Check conflicting trust/block entries
	for key := range trustedMap {
		if blockedMap[key] {
			return nil, PackValidationError{Code: 1, Err: fmt.Errorf("conflicting entry found in both trusted and blocked lists: %s", key)}
		}
	}

	// 6. Validate exceptions.yaml
	if excBytes, present := files["exceptions.yaml"]; present {
		excConfig, err := ParseExceptions(excBytes)
		if err != nil {
			return nil, PackValidationError{Code: 1, Err: err}
		}
		if err := ValidateExceptions(excConfig); err != nil {
			return nil, PackValidationError{Code: 1, Err: err}
		}
		// Expired exceptions fail validation
		for _, exc := range excConfig.Exceptions {
			if exc.IsExpired() {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("exception %s is expired", exc.ID)}
			}
		}
	}

	// 7. Validate scopes.yaml
	if scopesBytes, present := files["scopes.yaml"]; present {
		var scopesConfig ScopesConfig
		if err := yaml.Unmarshal(scopesBytes, &scopesConfig); err != nil {
			// try direct list
			var list []ScopedRule
			if err2 := yaml.Unmarshal(scopesBytes, &list); err2 == nil {
				scopesConfig.ScopedRules = list
			} else {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid scopes.yaml YAML syntax: %w", err)}
			}
		}
		for _, rule := range scopesConfig.ScopedRules {
			if rule.ID == "" {
				return nil, PackValidationError{Code: 1, Err: fmt.Errorf("scoped rule id cannot be empty")}
			}
			// Check wildcard scope
			if rule.Match.Package != "" {
				if strings.Contains(rule.Match.Package, "*") && !strings.HasSuffix(rule.Match.Package, "*") {
					return nil, PackValidationError{Code: 1, Err: fmt.Errorf("invalid wildcard scope in match: %s", rule.Match.Package)}
				}
			}
		}
	}

	return files, nil
}

func cleanPackPath(name string) (string, bool) {
	// Reject Windows drive paths (e.g. C:\...) or paths containing drive letters/colons
	if strings.Contains(name, ":") {
		return "", false
	}

	// Normalise path separators to forward slash
	norm := strings.ReplaceAll(name, "\\", "/")

	// Reject absolute paths
	if strings.HasPrefix(norm, "/") || filepath.IsAbs(name) || filepath.IsAbs(norm) {
		return "", false
	}

	// Reject UNC paths or double-slashes at start
	if strings.HasPrefix(norm, "//") || strings.HasPrefix(name, "\\\\") {
		return "", false
	}

	// Split and check each component for path traversal
	parts := strings.Split(norm, "/")
	for _, part := range parts {
		if part == ".." {
			return "", false
		}
	}

	// Use filepath.Clean to resolve relative dot segments
	clean := filepath.Clean(norm)

	// Reject if clean path is empty, dot, relative upwards, or absolute
	if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "..\\") || filepath.IsAbs(clean) {
		return "", false
	}

	return clean, true
}
