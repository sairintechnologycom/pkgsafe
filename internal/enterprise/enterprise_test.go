package enterprise_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/enterprise"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/types"
	"github.com/niyam-ai/pkgsafe/internal/version"
	"gopkg.in/yaml.v3"
)

func createTestTarGz(t *testing.T, files map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	tmpFile := filepath.Join(t.TempDir(), "test-pack.tar.gz")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return tmpFile
}

func TestPolicyPackMetadataParsing(t *testing.T) {
	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01",
		"description": "Standard enterprise PkgSafe policy pack",
		"owner": "Platform Engineering",
		"created_at": "2026-06-23T00:00:00Z",
		"expires_at": "2026-12-31T23:59:59Z",
		"compatibility": {
			"min_pkgsafe_version": "0.1.0"
		},
		"default_mode": "warn",
		"environments": ["developer", "ci", "ai_agent"]
	}`

	var meta enterprise.Metadata
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		t.Fatal(err)
	}

	if meta.Name != "enterprise-standard" || meta.Version != "2026.06.01" {
		t.Errorf("unexpected name or version: %s %s", meta.Name, meta.Version)
	}
	if meta.Compatibility.MinPkgSafeVersion != "0.1.0" {
		t.Errorf("unexpected min version: %s", meta.Compatibility.MinPkgSafeVersion)
	}
	if meta.IsExpired() {
		t.Errorf("expected metadata to not be expired yet")
	}
}

func TestPolicyPackInstallAndList(t *testing.T) {
	// Setup custom home dir for the test to avoid overwriting real ~/.pkgsafe
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01",
		"owner": "Platform Engineering",
		"expires_at": "2029-12-31T23:59:59Z",
		"compatibility": {
			"min_pkgsafe_version": "0.1.0"
		}
	}`

	checksumsText := ""
	h := sha256.New()
	h.Write([]byte(metaJSON))
	checksumsText += fmt.Sprintf("%s  metadata.json\n", hex.EncodeToString(h.Sum(nil)))

	packFiles := map[string][]byte{
		"metadata.json": []byte(metaJSON),
		"checksums.txt": []byte(checksumsText),
	}

	tarGzPath := createTestTarGz(t, packFiles)

	// Verify and Install
	_, verifyErr := enterprise.VerifyPolicyPack(tarGzPath)
	if verifyErr != nil {
		t.Fatalf("verification failed: %v", verifyErr)
	}

	installErr := enterprise.InstallPolicyPack(tarGzPath)
	if installErr != nil {
		t.Fatalf("installation failed: %v", installErr)
	}

	// List packs
	packs, err := enterprise.ListPolicyPacks()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, p := range packs {
		if p.Name == "enterprise-standard" && p.Version == "2026.06.01" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("installed policy pack not listed in %+v", packs)
	}
}

func TestPolicyPackVerifyChecksumFailure(t *testing.T) {
	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01"
	}`

	// Write wrong checksum
	checksumsText := "wrongchecksum  metadata.json\n"

	packFiles := map[string][]byte{
		"metadata.json": []byte(metaJSON),
		"checksums.txt": []byte(checksumsText),
	}

	tarGzPath := createTestTarGz(t, packFiles)

	_, err := enterprise.VerifyPolicyPack(tarGzPath)
	if err == nil {
		t.Fatalf("expected verification failure due to checksum mismatch")
	}
}

func TestPolicyPackPathTraversal(t *testing.T) {
	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01"
	}`

	maliciousPaths := []string{
		"../../evil.json",
		"/tmp/evil.json",
		"C:\\evil.json",
		"nested/../../../evil.json",
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			checksumsText := ""
			h := sha256.New()
			h.Write([]byte(metaJSON))
			checksumsText += fmt.Sprintf("%s  metadata.json\n", hex.EncodeToString(h.Sum(nil)))

			packFiles := map[string][]byte{
				"metadata.json": []byte(metaJSON),
				"checksums.txt": []byte(checksumsText),
				malPath:         []byte("malicious content"),
			}

			tarGzPath := createTestTarGz(t, packFiles)

			_, err := enterprise.VerifyPolicyPack(tarGzPath)
			if err == nil {
				t.Fatalf("expected verification failure for path %q", malPath)
			}
			if !strings.Contains(err.Error(), "unsafe file path in policy pack") {
				t.Errorf("expected unsafe path error, got %v", err)
			}
		})
	}
}

func TestPolicyPackExtractedSizeLimit(t *testing.T) {
	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01"
	}`

	largeFileContent := make([]byte, 51*1024*1024) // 51 MB, exceeding 50 MB limit

	checksumsText := ""
	h := sha256.New()
	h.Write([]byte(metaJSON))
	checksumsText += fmt.Sprintf("%s  metadata.json\n", hex.EncodeToString(h.Sum(nil)))
	h2 := sha256.New()
	h2.Write(largeFileContent)
	checksumsText += fmt.Sprintf("%s  large.db\n", hex.EncodeToString(h2.Sum(nil)))

	packFiles := map[string][]byte{
		"metadata.json": []byte(metaJSON),
		"checksums.txt": []byte(checksumsText),
		"large.db":      largeFileContent,
	}

	tarGzPath := createTestTarGz(t, packFiles)

	_, err := enterprise.VerifyPolicyPack(tarGzPath)
	if err == nil {
		t.Fatalf("expected verification failure due to size limit exceeded")
	}
	if !strings.Contains(err.Error(), "policy pack extracted size exceeds limit") {
		t.Errorf("expected size limit error, got %v", err)
	}
}

func TestPolicyPackExpiredAndMinVersion(t *testing.T) {
	// The min-version gate is skipped for dev builds, so pin a concrete
	// version below the pack's required 0.8.0 to exercise the comparison.
	prevVersion := version.Version
	version.Version = "0.1.0"
	t.Cleanup(func() { version.Version = prevVersion })

	// 1. Expired pack check
	expiredMeta := enterprise.Metadata{
		SchemaVersion: "1.0",
		Name:          "expired-pack",
		Version:       "1.0.0",
		ExpiresAt:     time.Now().Add(-1 * time.Hour),
	}
	if !expiredMeta.IsExpired() {
		t.Errorf("expected expired pack to report expired")
	}

	// 2. Minimum version check
	// Policy pack min version is 0.8.0, and our pkgsafe is hardcoded as 0.1.0.
	// ResolvePolicy should return error.
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01",
		"owner": "Platform Engineering",
		"compatibility": {
			"min_pkgsafe_version": "0.8.0"
		}
	}`
	policyYAML := `
mode: warn
`
	checksumsText := ""
	h := sha256.New()
	h.Write([]byte(metaJSON))
	checksumsText += fmt.Sprintf("%s  metadata.json\n", hex.EncodeToString(h.Sum(nil)))

	h2 := sha256.New()
	h2.Write([]byte(policyYAML))
	checksumsText += fmt.Sprintf("%s  policy.yaml\n", hex.EncodeToString(h2.Sum(nil)))

	packFiles := map[string][]byte{
		"metadata.json": []byte(metaJSON),
		"policy.yaml":   []byte(policyYAML),
		"checksums.txt": []byte(checksumsText),
	}

	tarGzPath := createTestTarGz(t, packFiles)
	err := enterprise.InstallPolicyPack(tarGzPath)
	if err == nil {
		t.Fatalf("expected version compatibility error during installation")
	}
	if !strings.Contains(err.Error(), "below the minimum required version") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPolicyValidationConflicts(t *testing.T) {
	// Conflicting trust/block entries
	pol := policy.Default()
	pol.TrustedPackageRules = []policy.TrustedPackageRule{
		{Name: "axios", Reason: "Approved"},
	}
	pol.BlockedPackageRules = []policy.BlockedPackageRule{
		{Name: "axios", Reason: "Malicious"},
	}

	err := policy.Validate(pol)
	if err == nil {
		t.Fatalf("expected validation error due to conflicting trust/block rules")
	}
	if !strings.Contains(err.Error(), "conflicting entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPolicyValidationExpiredException(t *testing.T) {
	pol := policy.Default()
	pol.Exceptions = []policy.Exception{
		{
			ID:           "EXC-01",
			Package:      "axios",
			AllowedUntil: time.Now().Add(-1 * time.Hour),
		},
	}

	err := policy.Validate(pol)
	if err == nil {
		t.Fatalf("expected validation error due to expired exception")
	}
	if !strings.Contains(err.Error(), "is expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTrustedAndBlockedPackageRules(t *testing.T) {
	pol := policy.Default()
	pol.TrustedPackageRules = []policy.TrustedPackageRule{
		{
			Name:         "@company/*",
			Registry:     "company",
			Reason:       "Approved internal scope",
			VersionRange: "*",
		},
		{
			Name:         "requests",
			VersionRange: ">=2.31.0",
			Reason:       "Approved requests version",
		},
	}
	pol.BlockedPackageRules = []policy.BlockedPackageRule{
		{
			Name:         "ctx",
			VersionRange: "*",
			Reason:       "Known malicious",
			Severity:     "critical",
		},
		{
			Name:         "requests",
			VersionRange: "<2.31.0",
			Reason:       "Vulnerable requests version",
			Severity:     "high",
		},
	}

	// 1. Matches trusted exact PyPI prefix/npm scope
	rule, matched := policy.FindTrustedPackageRule(pol, "npm", "@company/design-system", "1.0.0", "company")
	if !matched || rule.Name != "@company/*" {
		t.Errorf("expected @company/* rule to match")
	}

	// 2. Blocked overrides trust
	pkg := types.PackageIdentity{Ecosystem: "pypi", Name: "requests", Version: "2.30.0"}
	blockRule, blockedMatched := policy.FindBlockedPackageRule(pol, "pypi", pkg.Name, pkg.Version, "")
	if !blockedMatched || blockRule.Severity != "high" {
		t.Errorf("expected requests version 2.30.0 to be blocked")
	}

	// 3. ScanResult evaluation respect blocks & override trust
	res := types.ScanResult{
		Package:  pkg,
		Score:    5,
		Decision: types.DecisionAllow,
	}

	res = risk.ApplyEnterpriseControls(res, pol, "", policy.RegistryConfig{Type: "public"}, "human", "developer")
	if res.Decision != types.DecisionBlock {
		t.Errorf("expected requests 2.30.0 to be blocked under enterprise controls, got %s", res.Decision)
	}
}

func TestActiveExceptions(t *testing.T) {
	pol := policy.Default()
	pol.Exceptions = []policy.Exception{
		{
			ID:                 "EXC-2026-001",
			Ecosystem:          "npm",
			Package:            "legacy-build-tool",
			VersionRange:       "<=1.4.2",
			AllowedUntil:       time.Now().Add(24 * time.Hour),
			Reason:             "Migration temp rule",
			MaxDecisionAllowed: "warn",
			ApprovedBy:         "security@company.com",
		},
	}

	pkg := types.PackageIdentity{Ecosystem: "npm", Name: "legacy-build-tool", Version: "1.4.2"}
	exc, matched := policy.FindActiveException(pol, pkg, "developer")
	if !matched || exc.ID != "EXC-2026-001" {
		t.Fatalf("expected EXC-2026-001 exception to match")
	}

	// If decision is BLOCK, matching exception should downgrade it to WARN
	res := types.ScanResult{
		Package:  pkg,
		Score:    85,
		Decision: types.DecisionBlock,
	}
	res = risk.ApplyEnterpriseControls(res, pol, "default", policy.RegistryConfig{Type: "public"}, "human", "developer")

	if res.Decision != types.DecisionWarn {
		t.Errorf("expected exception to downgrade block to warn, got %s", res.Decision)
	}
	if res.ExceptionInfo == nil || !res.ExceptionInfo.Matched || res.ExceptionInfo.RuleID != "EXC-2026-001" {
		t.Errorf("expected exception info to be populated in ScanResult")
	}
}

func TestDependencyConfusionCandidates(t *testing.T) {
	// Dependency confusion candidate is when a package matches a private scope/prefix
	// but resolves to a public registry URL.
	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"company": {
				URL:     "https://npm.company.com/",
				Type:    "private",
				Enabled: true,
				Scopes:  []string{"@company"},
			},
		},
	}

	// axios resolves to default (public)
	regName, regCfg := registry.ResolveRegistry("npm", "axios", pol)
	if regName != "default" || regCfg.Type != "public" {
		t.Errorf("expected axios to resolve to default public registry")
	}

	// @company/pkg resolves to company (private)
	regName2, regCfg2 := registry.ResolveRegistry("npm", "@company/pkg", pol)
	if regName2 != "company" || regCfg2.Type != "private" {
		t.Errorf("expected @company/pkg to resolve to private registry, got %s %+v", regName2, regCfg2)
	}

	// Scenario where @company/pkg resolves to public registry (e.g. misconfigured)
	pkg := types.PackageIdentity{Ecosystem: "npm", Name: "@company/pkg", Version: "1.0.0"}
	res := types.ScanResult{
		Package:  pkg,
		Score:    5,
		Decision: types.DecisionAllow,
	}
	// Resolved registry is "default" (public) instead of "company"
	res = risk.ApplyEnterpriseControls(res, pol, "default", policy.RegistryConfig{Type: "public", URL: "https://registry.npmjs.org/"}, "human", "developer")
	if res.Decision != types.DecisionBlock {
		t.Errorf("expected dependency confusion candidate to be blocked, got %s", res.Decision)
	}

	hasConfIndicator := false
	for _, r := range res.Reasons {
		if r.ID == "dependency_confusion_candidate" || r.ID == "private_scope_public_registry" {
			hasConfIndicator = true
			break
		}
	}
	if !hasConfIndicator {
		t.Errorf("expected private_scope_public_registry reason to be set in ScanResult: %+v", res.Reasons)
	}
}

func TestOfflineBundles(t *testing.T) {
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	metaJSON := `{
		"schema_version": "1.0",
		"name": "enterprise-standard",
		"version": "2026.06.01",
		"owner": "Platform Engineering",
		"expires_at": "2029-12-31T23:59:59Z",
		"compatibility": {
			"min_pkgsafe_version": "0.1.0"
		}
	}`

	checksumsText := ""
	h := sha256.New()
	h.Write([]byte(metaJSON))
	checksumsText += fmt.Sprintf("%s  metadata.json\n", hex.EncodeToString(h.Sum(nil)))

	packFiles := map[string][]byte{
		"metadata.json": []byte(metaJSON),
		"checksums.txt": []byte(checksumsText),
	}

	tarGzPath := createTestTarGz(t, packFiles)
	if err := enterprise.InstallPolicyPack(tarGzPath); err != nil {
		t.Fatal(err)
	}

	// Export a bundle
	bundlePath := filepath.Join(t.TempDir(), "exported-bundle.tar.gz")
	pol := policy.Default()
	pol.PolicyPackName = "enterprise-standard"
	pol.PolicyPackVersion = "2026.06.01"

	// Create temp file for vulnerability DB to include
	dbPath := filepath.Join(t.TempDir(), "vuln.db")
	_ = os.WriteFile(dbPath, []byte("fake-db"), 0600)

	err := enterprise.ExportBundle(bundlePath)
	if err != nil {
		t.Fatalf("bundle export failed: %v", err)
	}

	// Reinstall from bundle
	reinstallErr := enterprise.InstallPolicyPack(bundlePath)
	if reinstallErr != nil {
		t.Fatalf("installing from bundle failed: %v", reinstallErr)
	}
}

func TestPolicyValidationInvalidRule(t *testing.T) {
	// Unknown rule ID validation check
	pol1 := policy.Default()
	pol1.Rules["unknown-rule-xyz"] = policy.Rule{
		Enabled:  true,
		Severity: "high",
		Score:    50,
	}
	err1 := policy.Validate(pol1)
	if err1 == nil {
		t.Fatal("expected policy validation to fail for unknown rule ID")
	}

	// Invalid severity validation check
	pol2 := policy.Default()
	pol2.Rules["known_malware_indicator"] = policy.Rule{
		Enabled:  true,
		Severity: "invalid-severity",
		Score:    100,
	}
	err2 := policy.Validate(pol2)
	if err2 == nil {
		t.Fatal("expected policy validation to fail for invalid severity")
	}

	// Invalid score validation check
	pol3 := policy.Default()
	pol3.Rules["known_malware_indicator"] = policy.Rule{
		Enabled:  true,
		Severity: "critical",
		Score:    999,
	}
	err3 := policy.Validate(pol3)
	if err3 == nil {
		t.Fatal("expected policy validation to fail for invalid score")
	}
}

func TestTrustedPyPIPackageByPrefix(t *testing.T) {
	pol := policy.Default()
	pol.TrustedPackageRules = []policy.TrustedPackageRule{
		{
			Name:         "company-*",
			Registry:     "company",
			Reason:       "Approved company package prefix",
			VersionRange: "*",
		},
	}

	rule, matched := policy.FindTrustedPackageRule(pol, "pypi", "company-core", "1.0.0", "company")
	if !matched || rule.Name != "company-*" {
		t.Errorf("expected PyPI prefix matching rule to match 'company-core'")
	}
}

func TestExpiredExceptionDoesNotApply(t *testing.T) {
	pol := policy.Default()
	pol.Exceptions = []policy.Exception{
		{
			ID:                 "EXC-EXPIRED",
			Ecosystem:          "npm",
			Package:            "expired-package",
			VersionRange:       "*",
			AllowedUntil:       time.Now().Add(-24 * time.Hour), // Expired!
			Reason:             "Should not apply",
			MaxDecisionAllowed: "warn",
			ApprovedBy:         "security@company.com",
		},
	}

	pkg := types.PackageIdentity{Ecosystem: "npm", Name: "expired-package", Version: "1.0.0"}
	_, matched := policy.FindActiveException(pol, pkg, "developer")
	if matched {
		t.Fatalf("expected expired exception to not match active list")
	}

	res := types.ScanResult{
		Package:  pkg,
		Score:    85,
		Decision: types.DecisionBlock,
	}
	res = risk.ApplyEnterpriseControls(res, pol, "default", policy.RegistryConfig{Type: "public"}, "human", "developer")

	if res.Decision != types.DecisionBlock {
		t.Errorf("expected ScanResult to remain blocked since the exception is expired, got %s", res.Decision)
	}
}

func TestExceptionCannotOverrideKnownMalware(t *testing.T) {
	pol := policy.Default()
	pol.Exceptions = []policy.Exception{
		{
			ID:                 "EXC-ALLOW-ALL",
			Ecosystem:          "npm",
			Package:            "malicious-pkg",
			VersionRange:       "*",
			AllowedUntil:       time.Now().Add(24 * time.Hour),
			Reason:             "Try to override malware",
			MaxDecisionAllowed: "warn",
			ApprovedBy:         "security@company.com",
		},
	}

	pkg := types.PackageIdentity{Ecosystem: "npm", Name: "malicious-pkg", Version: "1.0.0"}
	res := types.ScanResult{
		Package:  pkg,
		Score:    100,
		Decision: types.DecisionBlock,
		Reasons: []types.Reason{
			{
				ID:          "known_malware_indicator",
				Severity:    "critical",
				Description: "Contains known malware",
				ScoreImpact: 100,
			},
		},
	}

	res = risk.ApplyEnterpriseControls(res, pol, "default", policy.RegistryConfig{Type: "public"}, "human", "developer")
	if res.Decision != types.DecisionBlock {
		t.Errorf("expected exception to NOT downgrade block to warn when known malware is present, got %s", res.Decision)
	}
}

func TestRegistryConfigParsing(t *testing.T) {
	// Parse registries.yaml content
	registriesYAML := `
registries:
  npm:
    company:
      url: "https://npm.company.com/"
      type: private
      enabled: true
      scopes:
        - "@company"
      auth:
        method: env_token
        token_env: "COMPANY_NPM_TOKEN"
`
	var regMap map[string]map[string]interface{}
	err := yaml.Unmarshal([]byte(registriesYAML), &regMap)
	if err != nil {
		t.Fatalf("failed to parse registries YAML: %v", err)
	}

	regs, exists := regMap["registries"]
	if !exists {
		t.Fatal("missing registries section")
	}

	npmRegs := regs["npm"].(map[string]interface{})
	companyReg := npmRegs["company"].(map[string]interface{})
	if companyReg["url"] != "https://npm.company.com/" {
		t.Errorf("unexpected registry url: %v", companyReg["url"])
	}
}

func TestHTTPRegistryWarning(t *testing.T) {
	pol := policy.Default()
	pkg := types.PackageIdentity{Ecosystem: "npm", Name: "test-pkg", Version: "1.0.0"}

	// Unsecure HTTP registry URL
	res := types.ScanResult{
		Package:  pkg,
		Score:    0,
		Decision: types.DecisionAllow,
	}

	res = risk.ApplyEnterpriseControls(res, pol, "custom-http", policy.RegistryConfig{Type: "private", URL: "http://npm.insecure.com/"}, "human", "developer")

	hasHTTPWarning := false
	for _, r := range res.Reasons {
		if r.ID == "http_registry_warning" {
			hasHTTPWarning = true
			break
		}
	}
	if !hasHTTPWarning {
		t.Errorf("expected http_registry_warning reason for insecure URL")
	}
}

func TestUnapprovedRegistryURLBlocked(t *testing.T) {
	pol := policy.Default()
	pkg := types.PackageIdentity{Ecosystem: "npm", Name: "test-pkg", Version: "1.0.0"}
	res := types.ScanResult{
		Package:  pkg,
		Score:    0,
		Decision: types.DecisionAllow,
	}

	// Passing empty registry name signifies unapproved URL
	res = risk.ApplyEnterpriseControls(res, pol, "", policy.RegistryConfig{Type: "unknown", URL: "https://npm.unapproved.com/"}, "human", "developer")
	if res.Decision != types.DecisionBlock {
		t.Errorf("expected package from unapproved registry to be blocked, got %s", res.Decision)
	}
}

func TestPyPIPrivatePrefixUsesNormalizedName(t *testing.T) {
	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"pypi": {
			"company": {
				Type:            "private",
				URL:             "https://pypi.company.test/simple/",
				Enabled:         true,
				PackagePrefixes: []string{"company-internal"},
			},
		},
	}
	res := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "pypi", Name: "company_internal_pkg", Version: "1.0.0"},
		Score:    0,
		Decision: types.DecisionAllow,
	}
	res = risk.ApplyEnterpriseControls(res, pol, "default", policy.RegistryConfig{Type: "public", URL: "https://pypi.org/simple/"}, "human", "developer")
	found := false
	for _, r := range res.Reasons {
		if r.ID == "dependency_confusion_candidate" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected normalized PyPI private prefix to produce dependency confusion finding: %+v", res.Reasons)
	}
}

func TestTokensRedacted(t *testing.T) {
	secretURL := "https://myusername:mypassword@npm.company.com/path"
	redactedURL := registry.RedactURL(secretURL)
	if strings.Contains(redactedURL, "myusername") || strings.Contains(redactedURL, "mypassword") {
		t.Errorf("expected URL secrets to be redacted: %s", redactedURL)
	}

	secretOutput := "Bearer abc123def456xyz"
	redactedOutput := registry.RedactSecrets(secretOutput)
	if strings.Contains(redactedOutput, "abc123def456xyz") {
		t.Errorf("expected bearer token to be redacted: %s", redactedOutput)
	}
}
