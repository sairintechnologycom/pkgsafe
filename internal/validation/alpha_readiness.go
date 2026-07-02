package validation

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
	"github.com/sairintechnologycom/pkgsafe/internal/mcp"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	rnpm "github.com/sairintechnologycom/pkgsafe/internal/registry/npm"
	rpypi "github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/report"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type AlphaReadinessReport struct {
	Pass                        bool            `json:"pass"`
	CriticalDetectionRate       float64         `json:"critical_detection_rate"`
	FalseBlockRate              float64         `json:"false_block_rate"`
	SecretLeakageCount          int             `json:"secret_leakage_count"`
	UnsafeArchiveAcceptedCount  int             `json:"unsafe_archive_accepted_count"`
	PrivateRegistryLeakageCount int             `json:"private_registry_leakage_count"`
	MCPStdoutPollutionCount     int             `json:"mcp_stdout_pollution_count"`
	FinalReadiness              string          `json:"final_readiness"` // INTERNAL_ALPHA_READY or BLOCKED
	Gates                       map[string]bool `json:"gates"`
}

func RunAlphaReadiness(corpusDir, goldenFile string) (AlphaReadinessReport, error) {
	rep := AlphaReadinessReport{
		Pass:  true,
		Gates: make(map[string]bool),
	}

	// 1. Corpus Validation Gate
	corpusReport, err := RunCorpusReport(corpusDir, goldenFile)
	if err != nil {
		rep.Gates["corpus_validation"] = false
		rep.Pass = false
	} else {
		rep.CriticalDetectionRate = corpusReport.Metrics.CriticalDetectionRate
		rep.FalseBlockRate = corpusReport.Metrics.FalseBlockRate
		// Check that all results passed
		corpusPass := true
		for _, res := range corpusReport.Results {
			if !res.Passed {
				corpusPass = false
				break
			}
		}
		rep.Gates["corpus_validation"] = corpusPass
		if !corpusPass {
			rep.Pass = false
		}
	}

	// 2. Security Extraction Hardening Gate
	unsafeArchiveCount := runExtractionHardeningTests()
	rep.UnsafeArchiveAcceptedCount = unsafeArchiveCount
	rep.Gates["security_extraction"] = (unsafeArchiveCount == 0)
	if unsafeArchiveCount > 0 {
		rep.Pass = false
	}

	// 3. Secret Redaction Gate
	secretLeakCount := runSecretRedactionTests()
	rep.SecretLeakageCount = secretLeakCount
	rep.Gates["redaction"] = (secretLeakCount == 0)
	if secretLeakCount > 0 {
		rep.Pass = false
	}

	// 4. Registry Routing Gate
	registryLeakCount := runRegistryRoutingTests()
	rep.PrivateRegistryLeakageCount = registryLeakCount
	rep.Gates["registry_routing"] = (registryLeakCount == 0)
	if registryLeakCount > 0 {
		rep.Pass = false
	}

	// 5. MCP Stdio Gate
	mcpPollutionCount := runMCPStdioTests()
	rep.MCPStdoutPollutionCount = mcpPollutionCount
	rep.Gates["mcp_stdio"] = (mcpPollutionCount == 0)
	if mcpPollutionCount > 0 {
		rep.Pass = false
	}

	// 6. Install Enforcement Gate
	installEnforcementPass := runInstallEnforcementTests()
	rep.Gates["install_enforcement"] = installEnforcementPass
	if !installEnforcementPass {
		rep.Pass = false
	}

	if rep.Pass {
		rep.FinalReadiness = "INTERNAL_ALPHA_READY"
	} else {
		rep.FinalReadiness = "BLOCKED"
	}

	return rep, nil
}

// Helpers for Archive Extraction Hardening Tests
func createTarGzBytes(files map[string][]byte, symlinks map[string]string, hardlinks map[string]string, writeLargeHeader bool) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0600,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}

	for name, target := range symlinks {
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeSymlink,
			Linkname: target,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
	}

	for name, target := range hardlinks {
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeLink,
			Linkname: target,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
	}

	if writeLargeHeader {
		hdr := &tar.Header{
			Name:     "bomb.txt",
			Mode:     0600,
			Size:     101 * 1024 * 1024, // 101 MB (exceeds limit)
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func createZipBytes(files map[string][]byte, symlinks map[string]string, writeLargeHeader bool) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for name, content := range files {
		f, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(content); err != nil {
			return nil, err
		}
	}

	for name, target := range symlinks {
		hdr := &zip.FileHeader{
			Name: name,
		}
		hdr.SetMode(os.ModeSymlink | 0777)
		f, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write([]byte(target)); err != nil {
			return nil, err
		}
	}

	if writeLargeHeader {
		// zip.Writer recomputes UncompressedSize64 from the bytes actually written
		// on Close, so a manually-inflated header is reset to the real size. To
		// produce a genuine bomb we write real over-limit content; it compresses to
		// a few KB on disk but reports its true 101 MB uncompressed size, which the
		// extractor's budget check rejects before writing anything.
		f, err := zw.Create("bomb.txt")
		if err != nil {
			return nil, err
		}
		chunk := bytes.Repeat([]byte("A"), 1024*1024) // 1 MB
		for i := 0; i < 101; i++ {                    // 101 MB total (exceeds limit)
			if _, err := f.Write(chunk); err != nil {
				return nil, err
			}
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func runExtractionHardeningTests() int {
	failures := 0
	tmpDir, err := os.MkdirTemp("", "pkgsafe-extract-hardening-*")
	if err != nil {
		return 1
	}
	defer os.RemoveAll(tmpDir)

	runNPMTest := func(tarBytes []byte) bool {
		filePath := filepath.Join(tmpDir, "temp.tgz")
		_ = os.WriteFile(filePath, tarBytes, 0600)
		defer os.Remove(filePath)
		dest := filepath.Join(tmpDir, "npm-dest")
		_ = os.MkdirAll(dest, 0755)
		defer os.RemoveAll(dest)

		err := rnpm.ExtractTarball(filePath, dest)
		return err != nil
	}

	runPyPITest := func(archiveBytes []byte, isZip bool) bool {
		suffix := ".tar.gz"
		if isZip {
			suffix = ".zip"
		}
		filePath := filepath.Join(tmpDir, "temp"+suffix)
		_ = os.WriteFile(filePath, archiveBytes, 0600)
		defer os.Remove(filePath)
		dest := filepath.Join(tmpDir, "pypi-dest")
		_ = os.MkdirAll(dest, 0755)
		defer os.RemoveAll(dest)

		err := rpypi.ExtractArtifact(filePath, dest)
		return err != nil
	}

	// npm tarball path traversal
	travTar, _ := createTarGzBytes(map[string][]byte{"../../escaped.txt": []byte("content")}, nil, nil, false)
	if !runNPMTest(travTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm tarball path traversal accepted!")
		failures++
	}

	// PyPI artifact path traversal (tar)
	travPyTar, _ := createTarGzBytes(map[string][]byte{"../../escaped.txt": []byte("content")}, nil, nil, false)
	if !runPyPITest(travPyTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI artifact path traversal (tar) accepted!")
		failures++
	}

	// PyPI artifact path traversal (zip)
	travPyZip, _ := createZipBytes(map[string][]byte{"../../escaped.txt": []byte("content")}, nil, false)
	if !runPyPITest(travPyZip, true) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI artifact path traversal (zip) accepted!")
		failures++
	}

	// absolute paths
	absTar, _ := createTarGzBytes(map[string][]byte{"/tmp/escaped.txt": []byte("content")}, nil, nil, false)
	if !runNPMTest(absTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm absolute path accepted!")
		failures++
	}
	if !runPyPITest(absTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI absolute path accepted!")
		failures++
	}
	// Windows drive paths
	winTar, _ := createTarGzBytes(map[string][]byte{"C:\\escaped.txt": []byte("content")}, nil, nil, false)
	if !runNPMTest(winTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm Windows drive path accepted!")
		failures++
	}
	if !runPyPITest(winTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI Windows drive path accepted!")
		failures++
	}
	// symlink escape
	symTar, _ := createTarGzBytes(nil, map[string]string{"escaped-symlink": "../../etc/passwd"}, nil, false)
	if !runNPMTest(symTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm symlink accepted!")
		failures++
	}
	if !runPyPITest(symTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI symlink (tar) accepted!")
		failures++
	}
	symZip, _ := createZipBytes(nil, map[string]string{"escaped-symlink": "../../etc/passwd"}, false)
	if !runPyPITest(symZip, true) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI symlink (zip) accepted!")
		failures++
	}

	// hardlink escape
	hdrTar, _ := createTarGzBytes(nil, nil, map[string]string{"escaped-hardlink": "../../etc/passwd"}, false)
	if !runNPMTest(hdrTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm hardlink accepted!")
		failures++
	}
	if !runPyPITest(hdrTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI hardlink accepted!")
		failures++
	}
	// tar bomb file count limit
	// Create more than 5000 file entries
	countFiles := make(map[string][]byte)
	for i := 0; i < 5002; i++ {
		countFiles[fmt.Sprintf("file-%d.txt", i)] = []byte{}
	}
	cntTar, _ := createTarGzBytes(countFiles, nil, nil, false)
	if !runNPMTest(cntTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm tar bomb file count accepted!")
		failures++
	}
	if !runPyPITest(cntTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI tar bomb file count accepted!")
		failures++
	}

	cntZip, _ := createZipBytes(countFiles, nil, false)
	if !runPyPITest(cntZip, true) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI zip bomb file count accepted!")
		failures++
	}

	// tar bomb extracted byte limit
	byteTar, _ := createTarGzBytes(nil, nil, nil, true)
	if !runNPMTest(byteTar) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm tar bomb byte limit accepted!")
		failures++
	}
	if !runPyPITest(byteTar, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI tar bomb byte limit accepted!")
		failures++
	}
	byteZip, _ := createZipBytes(nil, nil, true)
	if !runPyPITest(byteZip, true) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI zip bomb byte limit accepted!")
		failures++
	}

	// malformed archive
	malBytes := []byte("corrupt-bytes-not-a-tar")
	if !runNPMTest(malBytes) {
		fmt.Fprintln(os.Stderr, "DEBUG: npm malformed tar accepted!")
		failures++
	}
	if !runPyPITest(malBytes, false) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI malformed tar accepted!")
		failures++
	}
	if !runPyPITest(malBytes, true) {
		fmt.Fprintln(os.Stderr, "DEBUG: PyPI malformed zip accepted!")
		failures++
	}
	return failures
}

// Helpers for Secret Redaction Tests
func runSecretRedactionTests() int {
	failures := 0

	secrets := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"NPM_TOKEN":             "npm_s7Y2Rz9F3Kj1Lm5Np9Qr2St8Uv4Wx1Yz",
		"GITHUB_TOKEN":          "ghp_fakeToken45678901234567890123456789",
		"STRIPE_SECRET":         "sk_test_secret1234567890123456789012",
	}

	for k, v := range secrets {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	basicAuthURL := "https://user:password@registry.company.com/"
	overrideReason := "Manual override reason containing npm_s7Y2Rz9F3Kj1Lm5Np9Qr2St8Uv4Wx1Yz and stripe sk_test_secret1234567890123456789012 key"

	// Mock report
	r := &report.RepositoryRiskReport{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Repository: report.RepositoryMetadata{
			Name: "test-repo",
		},
		Policy: report.PolicyMetadata{
			PackName:    "pack",
			PackVersion: "1.0.0",
		},
		Summary: report.RiskSummary{
			PackagesScanned: 1,
			Blocked:         1,
		},
		Findings: []report.ReportFinding{
			{
				Package:   "test-pkg",
				Version:   "1.0.0",
				Decision:  "block",
				RiskScore: 100,
				Severity:  "critical",
				RuleID:    "known_malware_indicator",
				Message:   "Malware containing " + basicAuthURL,
			},
		},
		Recommendations: []report.RecommendationRecord{
			{
				Type:    "block",
				Message: "Recommendation mentioning " + secrets["AWS_SECRET_ACCESS_KEY"],
			},
		},
		Overrides: []report.OverrideRecord{
			{
				Package:        "test-pkg",
				OverrideReason: overrideReason,
			},
		},
	}

	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"default": {
				URL: basicAuthURL,
			},
		},
	}

	// Test all exports
	checkLeakage := func(content string, name string) {
		for _, v := range secrets {
			if strings.Contains(content, v) {
				failures++
			}
		}
		// Look for an unredacted basic-auth credential (e.g. "user:password@").
		// Checking the bare word "password" produces false positives: it also
		// matches struct field names such as the "password_env" JSON key.
		if strings.Contains(content, ":password@") {
			failures++
		}
		// Confirm override reasons are redacted
		if strings.Contains(content, "sk_test_secret") {
			failures++
		}
	}

	if js, err := report.ExportJSON(r); err == nil {
		checkLeakage(js, "JSON")
	} else {
		failures++
	}

	if md, err := report.ExportMarkdown(r); err == nil {
		checkLeakage(md, "Markdown")
	} else {
		failures++
	}

	if html, err := report.ExportHTML(r); err == nil {
		checkLeakage(html, "HTML")
	} else {
		failures++
	}

	if sarif, err := report.ExportSarif(r); err == nil {
		checkLeakage(sarif, "Sarif")
	} else {
		failures++
	}

	tmpZip := filepath.Join(os.TempDir(), fmt.Sprintf("pkgsafe-evidence-%d.zip", time.Now().UnixNano()))
	defer os.Remove(tmpZip)
	if err := report.CreateEvidencePack(tmpZip, r, pol); err == nil {
		zr, err := zip.OpenReader(tmpZip)
		if err == nil {
			defer zr.Close()
			for _, f := range zr.File {
				rc, err := f.Open()
				if err == nil {
					b, _ := io.ReadAll(rc)
					rc.Close()
					checkLeakage(string(b), "EvidencePack:"+f.Name)
				}
			}
		} else {
			failures++
		}
	} else {
		failures++
	}

	return failures
}

// Helpers for Registry Routing Tests
func runRegistryRoutingTests() int {
	failures := 0

	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"default": {
				URL:     "https://registry.npmjs.org/",
				Type:    "public",
				Enabled: false, // fallback disabled!
			},
			"custom-npm": {
				URL:     "https://npm.company.internal/",
				Type:    "private",
				Enabled: true,
				Scopes:  []string{"@company"},
			},
		},
		"pypi": {
			"default": {
				URL:     "https://pypi.org/pypi/",
				Type:    "public",
				Enabled: false, // fallback disabled!
			},
			"custom-pypi": {
				URL:             "https://pypi.company.internal/",
				Type:            "private",
				Enabled:         true,
				PackagePrefixes: []string{"company-"},
			},
		},
	}

	// NPM scope matches private, never public
	regName, regCfg := registry.ResolveRegistry("npm", "@company/pkg", pol)
	if regName != "custom-npm" || regCfg.Type != "private" {
		failures++
	}

	// NPM scope public fallback disabled blocks unmatched packages
	scanner := snpm.New()
	scanner.Policy = pol
	scanner.Offline = true
	_, err := scanner.ScanPackage("axios", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "disabled by policy") {
		failures++
	}

	// PyPI prefix matches private, never public
	regName2, regCfg2 := registry.ResolveRegistry("pypi", "company-internal-pkg", pol)
	if regName2 != "custom-pypi" || regCfg2.Type != "private" {
		failures++
	}

	// Normalizations
	names := []string{"company_internal_pkg", "company.internal.pkg", "Company-Internal-Pkg"}
	for _, n := range names {
		rName, _ := registry.ResolveRegistry("pypi", n, pol)
		if rName != "custom-pypi" {
			failures++
		}
	}

	// Normalization directly
	if registry.NormalizePyPIName("company_internal_pkg") != "company-internal-pkg" {
		failures++
	}
	if registry.NormalizePyPIName("company.internal.pkg") != "company-internal-pkg" {
		failures++
	}
	if registry.NormalizePyPIName("Company-Internal-Pkg") != "company-internal-pkg" {
		failures++
	}

	return failures
}

// Helpers for MCP Stdio Integrity Tests
func runMCPStdioTests() int {
	failures := 0

	config := mcp.ServerConfig{
		LogLevel: "debug",
	}

	// Send raw JSON-RPC ping request
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","method":"ping","id":1}` + "\n")
	var out bytes.Buffer

	// We pass stdout to Serve which writes to out.
	// Serve with LogLevel=debug writes logs to stderr, NOT stdout.
	err := mcp.Serve(config, in, &out)
	if err != nil {
		failures++
	}

	output := out.String()
	if output == "" {
		failures++
	}

	// Assert output is JSON-RPC only
	var resp mcp.Response
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		failures++
	}
	if resp.JSONRPC != "2.0" {
		failures++
	}

	// Assert no pollution
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		failures++
	}

	return failures
}

// Helpers for Install Enforcement Tests
func runInstallEnforcementTests() bool {
	pol := policy.Default()

	// 1. Non-interactive warning blocks without --yes
	sfNo := intercept.SafetyFlags{Yes: false}
	proceedNo, _, _ := intercept.CanProceed(nil, types.DecisionWarn, sfNo, pol)
	if proceedNo {
		return false
	}

	// 2. Non-interactive warning proceeds with --yes
	sfYes := intercept.SafetyFlags{Yes: true}
	proceedYes, _, _ := intercept.CanProceed(nil, types.DecisionWarn, sfYes, pol)
	if !proceedYes {
		return false
	}

	// 3. Block never installs by default
	proceedBlock, _, _ := intercept.CanProceed(nil, types.DecisionBlock, sfNo, pol)
	if proceedBlock {
		return false
	}

	// 4. AI-agent context blocks WARN packages by default
	os.Setenv("PKGSAFE_REQUESTED_BY", "ai_agent")
	defer os.Unsetenv("PKGSAFE_REQUESTED_BY")
	proceedAI, _, _ := intercept.CanProceed(nil, types.DecisionWarn, sfYes, pol)
	if proceedAI {
		return false
	}

	return true
}
