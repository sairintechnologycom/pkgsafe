package validation

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	anpm "github.com/sairintechnologycom/pkgsafe/internal/analyzer/npm"
	npminventory "github.com/sairintechnologycom/pkgsafe/internal/deps/npm"
	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
	"github.com/sairintechnologycom/pkgsafe/internal/mcp"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/report"
	"github.com/sairintechnologycom/pkgsafe/internal/sandbox"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

const (
	ReadinessInternalAlpha = "INTERNAL_ALPHA_READY"
	ReadinessPrivateBeta   = "PRIVATE_BETA_READY"
	ReadinessPublicBeta    = "PUBLIC_BETA_READY"
	ReadinessProductionGA  = "PRODUCTION_GA_READY"
	ReadinessBlocked       = "BLOCKED"
)

type RolloutReadinessReport struct {
	GeneratedAt    string                 `json:"generated_at"`
	FinalStatus    string                 `json:"final_status"`
	Recommendation string                 `json:"recommendation"`
	Pass           bool                   `json:"pass"`
	Gates          []RolloutReadinessGate `json:"gates"`
}

type RolloutReadinessGate struct {
	Name       string   `json:"name"`
	Passed     bool     `json:"passed"`
	Blocking   bool     `json:"blocking"`
	DurationMs int64    `json:"duration_ms"`
	Summary    string   `json:"summary"`
	Details    []string `json:"details,omitempty"`
}

func RunRolloutReadiness(corpusDir, goldenFile string) (RolloutReadinessReport, error) {
	rep := RolloutReadinessReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	rep.Gates = append(rep.Gates,
		timedGate("build/test health", true, runBuildTestHealthGate),
		timedGate("corpus accuracy", false, func() (bool, string, []string) {
			return runCorpusAccuracyGate(corpusDir, goldenFile)
		}),
		timedGate("archive extraction security", true, runArchiveSecurityGate),
		timedGate("secret redaction", true, runSecretRedactionGate),
		timedGate("sandbox safety", true, runSandboxSafetyGate),
		timedGate("private registry leakage", true, runPrivateRegistryGate),
		timedGate("MCP stdio integrity", true, runMCPStdioGate),
		timedGate("install interception safety", true, runInstallInterceptionGate),
		timedGate("malformed input handling", true, runMalformedInputGate),
		timedGate("packaging artifact check", false, runPackagingGate),
	)

	blockingFailed := false
	anyFailed := false
	for _, gate := range rep.Gates {
		if !gate.Passed {
			anyFailed = true
			if gate.Blocking {
				blockingFailed = true
			}
		}
	}

	switch {
	case blockingFailed:
		rep.FinalStatus = ReadinessBlocked
		rep.Pass = false
		rep.Recommendation = "NO-GO: one or more security, execution safety, or health gates failed."
	case anyFailed:
		rep.FinalStatus = ReadinessInternalAlpha
		rep.Pass = false
		rep.Recommendation = "NO-GO for user rollout: core safety gates passed, but accuracy or packaging is not private-beta ready."
	default:
		rep.FinalStatus = ReadinessPrivateBeta
		rep.Pass = true
		rep.Recommendation = "GO for private beta rollout. Continue to keep lifecycle behavior analysis labelled best-effort."
	}

	return rep, nil
}

func WriteRolloutReadiness(w io.Writer, rep RolloutReadinessReport, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	fmt.Fprintln(w, "PkgSafe User Rollout Readiness Gate")
	fmt.Fprintln(w, "====================================")
	fmt.Fprintf(w, "%-34s %-8s %-10s %s\n", "Gate", "Status", "Blocking", "Summary")
	fmt.Fprintf(w, "%-34s %-8s %-10s %s\n", strings.Repeat("-", 34), strings.Repeat("-", 8), strings.Repeat("-", 10), strings.Repeat("-", 28))
	for _, gate := range rep.Gates {
		status := "PASS"
		if !gate.Passed {
			status = "FAIL"
		}
		blocking := "no"
		if gate.Blocking {
			blocking = "yes"
		}
		fmt.Fprintf(w, "%-34s %-8s %-10s %s\n", gate.Name, status, blocking, gate.Summary)
		for _, detail := range gate.Details {
			fmt.Fprintf(w, "  - %s\n", detail)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Final Status: %s\n", rep.FinalStatus)
	fmt.Fprintf(w, "Recommendation: %s\n", rep.Recommendation)
	return nil
}

func timedGate(name string, blocking bool, fn func() (bool, string, []string)) RolloutReadinessGate {
	start := time.Now()
	passed, summary, details := safeGate(fn)
	return RolloutReadinessGate{
		Name:       name,
		Passed:     passed,
		Blocking:   blocking,
		DurationMs: time.Since(start).Milliseconds(),
		Summary:    summary,
		Details:    details,
	}
}

func safeGate(fn func() (bool, string, []string)) (passed bool, summary string, details []string) {
	defer func() {
		if r := recover(); r != nil {
			passed = false
			summary = "gate panicked"
			details = []string{fmt.Sprintf("panic: %v", r)}
		}
	}()
	return fn()
}

func runBuildTestHealthGate() (bool, string, []string) {
	commands := [][]string{
		{"go", "test", "./..."},
		{"go", "test", "-race", "./..."},
		{"go", "vet", "./..."},
	}
	var details []string
	for _, args := range commands {
		out, err := runRepoCommand(args...)
		cmdText := strings.Join(args, " ")
		if err != nil {
			details = append(details, fmt.Sprintf("%s failed: %v", cmdText, err))
			if trimmed := strings.TrimSpace(out); trimmed != "" {
				details = append(details, lastLines(trimmed, 12)...)
			}
			return false, cmdText + " failed", details
		}
		details = append(details, cmdText+" passed")
	}
	return true, "go test, race test, and vet passed", details
}

func runRepoCommand(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(os.TempDir(), "pkgsafe-rollout-gocache"))
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("timed out")
	}
	return string(out), err
}

func runCorpusAccuracyGate(corpusDir, goldenFile string) (bool, string, []string) {
	rep, err := RunCorpusReport(corpusDir, goldenFile)
	if err != nil {
		return false, "corpus run failed", []string{err.Error()}
	}
	details := []string{
		fmt.Sprintf("critical detection rate: %.2f%% (required 100.00%%)", rep.Metrics.CriticalDetectionRate*100),
		fmt.Sprintf("false block rate: %.2f%% (required 0.00%%)", rep.Metrics.FalseBlockRate*100),
		fmt.Sprintf("direct dependency recall: %.2f%% (required >= 95.00%%)", rep.Metrics.DirectDependencyRecall*100),
		fmt.Sprintf("transitive dependency recall: %.2f%% (required >= 90.00%%)", rep.Metrics.TransitiveDependencyRecall*100),
		fmt.Sprintf("source import recall: %.2f%% (required >= 85.00%%)", rep.Metrics.SourceImportRecall*100),
	}
	passed := rep.Metrics.CriticalDetectionRate == 1 &&
		rep.Metrics.FalseBlockRate == 0 &&
		rep.Metrics.DirectDependencyRecall >= 0.95 &&
		rep.Metrics.TransitiveDependencyRecall >= 0.90 &&
		rep.Metrics.SourceImportRecall >= 0.85
	if !passed {
		for _, fixture := range rep.Results {
			if !fixture.Passed {
				details = append(details, fmt.Sprintf("fixture %s failed: %s", fixture.Fixture, strings.Join(fixture.Details, "; ")))
			}
		}
		return false, "accuracy thresholds not met", details
	}
	return true, "accuracy thresholds met", details
}

func runArchiveSecurityGate() (bool, string, []string) {
	failures := runExtractionHardeningTests()
	if failures > 0 {
		return false, "unsafe archive input was accepted", []string{fmt.Sprintf("%d archive hardening subchecks failed", failures)}
	}
	return true, "path traversal, absolute paths, links, bombs, and malformed archives rejected", nil
}

func runSecretRedactionGate() (bool, string, []string) {
	failures, details := countSecretRedactionLeaks()
	if failures > 0 {
		return false, "fake secrets leaked in generated output", details
	}
	return true, "fake secrets were redacted from all generated outputs", details
}

func countSecretRedactionLeaks() (int, []string) {
	secrets := map[string]string{
		"STRIPE_KEY":            "sk_test_rolloutStripeSecret123456789012",
		"GEMINI_API_KEY":        "AIzaSyRolloutFakeGeminiKey123456789",
		"GH_TOKEN":              "ghp_rolloutFakeToken123456789012345678",
		"AWS_ACCESS_KEY_ID":     "AKIAROLLOUTFAKE1234",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"NPM_TOKEN":             "npm_rolloutFakeToken123456789012345678",
		"DB_PASSWORD":           "rollout-db-password-123456",
	}
	for k, v := range secrets {
		_ = os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	basicAuthURL := "https://user:rollout-db-password-123456@registry.company.com/"
	r := &report.RepositoryRiskReport{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Repository: report.RepositoryMetadata{
			Name: "repo-" + secrets["GH_TOKEN"],
		},
		Policy: report.PolicyMetadata{
			PackName:    "pack-" + secrets["NPM_TOKEN"],
			PackVersion: "1.0.0",
		},
		Summary: report.RiskSummary{PackagesScanned: 1, Blocked: 1},
		Findings: []report.ReportFinding{{
			Package:   "pkg-" + secrets["STRIPE_KEY"],
			Version:   "1.0.0",
			Decision:  "block",
			RiskScore: 100,
			Severity:  "critical",
			RuleID:    "secret_keyword_reference",
			Message:   "contains " + secrets["GEMINI_API_KEY"] + " and " + basicAuthURL,
		}},
		Recommendations: []report.RecommendationRecord{{
			Type:    "block",
			Message: "rotate " + secrets["AWS_ACCESS_KEY_ID"] + " " + secrets["AWS_SECRET_ACCESS_KEY"],
		}},
		Overrides: []report.OverrideRecord{{
			Package:        "pkg",
			OverrideReason: "manual approval contained " + secrets["DB_PASSWORD"],
		}},
	}
	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {"default": {URL: basicAuthURL}},
	}

	outputs := map[string]string{}
	add := func(name string, content string, err error) {
		if err != nil {
			outputs[name] = "EXPORT_ERROR:" + err.Error()
			return
		}
		outputs[name] = content
	}
	content, err := report.ExportJSON(r)
	add("JSON", content, err)
	content, err = report.ExportSarif(r)
	add("SARIF", content, err)
	content, err = report.ExportMarkdown(r)
	add("Markdown", content, err)
	content, err = report.ExportHTML(r)
	add("HTML", content, err)
	content, err = report.ExportSIEM(r)
	add("SIEM JSONL", content, err)
	content, err = report.ExportServiceNow(r)
	add("ServiceNow JSON", content, err)
	content, err = report.ExportAzureDevOps(r)
	add("Azure DevOps Markdown", content, err)

	tmpZip := filepath.Join(os.TempDir(), fmt.Sprintf("pkgsafe-rollout-evidence-%d.zip", time.Now().UnixNano()))
	defer os.Remove(tmpZip)
	if err := report.CreateEvidencePack(tmpZip, r, pol); err != nil {
		outputs["evidence pack"] = "EXPORT_ERROR:" + err.Error()
	} else {
		zr, err := zip.OpenReader(tmpZip)
		if err != nil {
			outputs["evidence pack"] = "EXPORT_ERROR:" + err.Error()
		} else {
			defer zr.Close()
			var buf strings.Builder
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				b, _ := io.ReadAll(rc)
				_ = rc.Close()
				buf.Write(b)
				buf.WriteByte('\n')
			}
			outputs["evidence pack"] = buf.String()
		}
	}

	var leaks int
	var details []string
	names := make([]string, 0, len(outputs))
	for name := range outputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := outputs[name]
		if strings.HasPrefix(content, "EXPORT_ERROR:") {
			leaks++
			details = append(details, name+" generation failed: "+strings.TrimPrefix(content, "EXPORT_ERROR:"))
			continue
		}
		for secretName, secretValue := range secrets {
			if strings.Contains(content, secretValue) {
				leaks++
				details = append(details, fmt.Sprintf("%s leaked %s", name, secretName))
			}
		}
		if strings.Contains(content, ":rollout-db-password-123456@") {
			leaks++
			details = append(details, name+" leaked basic-auth password")
		}
	}
	if len(details) == 0 {
		details = append(details, "checked JSON, SARIF, Markdown, HTML, SIEM JSONL, ServiceNow JSON, Azure DevOps Markdown, and evidence pack")
	}
	return leaks, details
}

func runSandboxSafetyGate() (bool, string, []string) {
	root, err := os.MkdirTemp("", "pkgsafe-rollout-sandbox-*")
	if err != nil {
		return false, "could not create sandbox probe directory", []string{err.Error()}
	}
	defer os.RemoveAll(root)

	sensitive := map[string]string{
		"ROLLOUT_TOKEN":      "token",
		"ROLLOUT_KEY":        "key",
		"ROLLOUT_SECRET":     "secret",
		"ROLLOUT_PASSWORD":   "password",
		"ROLLOUT_AUTH":       "auth",
		"ROLLOUT_COOKIE":     "cookie",
		"ROLLOUT_SESSION":    "session",
		"ROLLOUT_CREDENTIAL": "credential",
	}
	for k, v := range sensitive {
		_ = os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	env := sandbox.CleanEnv(root)
	envMap := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			envMap[k] = v
		}
	}

	required := map[string]string{
		"HOME":            filepath.Join(root, "home"),
		"USERPROFILE":     filepath.Join(root, "home"),
		"XDG_CONFIG_HOME": filepath.Join(root, "home", ".config"),
		"XDG_CACHE_HOME":  filepath.Join(root, "home", ".cache"),
		"XDG_DATA_HOME":   filepath.Join(root, "home", ".local", "share"),
		"TMPDIR":          filepath.Join(root, "tmp"),
		"TEMP":            filepath.Join(root, "tmp"),
		"TMP":             filepath.Join(root, "tmp"),
	}

	var details []string
	for key, want := range required {
		if got := envMap[key]; filepath.Clean(got) != filepath.Clean(want) {
			details = append(details, fmt.Sprintf("%s not redirected into sandbox root (got %q, want %q)", key, got, want))
		}
	}
	for key := range sensitive {
		if _, ok := envMap[key]; ok {
			details = append(details, key+" was not dropped")
		}
	}

	label := "best-effort"
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		label = "unavailable"
	}
	details = append(details, "fake-home runner isolation label: "+label)
	details = append(details, "strong isolation backend detected: false")

	if len(details) > 2 {
		return false, "sandbox environment redirection or secret dropping failed", details
	}
	return true, "host env is cleaned and fake-home runner is labelled best-effort", details
}

func runPrivateRegistryGate() (bool, string, []string) {
	failures := runRegistryRoutingTests()
	details := []string{
		"checked @company npm scope resolves to private registry",
		"checked PyPI company_internal_pkg, company.internal.pkg, and Company-Internal-Pkg normalize to company-internal-pkg",
		"checked disabled public fallback blocks unmatched npm and PyPI packages",
	}

	pol := rolloutRegistryPolicy()
	pypiScanner := spypi.New()
	pypiScanner.Policy = pol
	pypiScanner.Offline = true
	if _, err := pypiScanner.ScanPackage("requests", "2.31.0"); err == nil || !strings.Contains(err.Error(), "disabled by policy") {
		failures++
		details = append(details, "unmatched PyPI package was not blocked when public fallback was disabled")
	}

	if failures > 0 {
		return false, "private registry routing leaked or fallback did not fail closed", details
	}
	return true, "private package patterns do not route to public fallback", details
}

func rolloutRegistryPolicy() policy.Policy {
	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"default": {URL: "https://registry.npmjs.org/", Type: "public", Enabled: false},
			"internal": {URL: "https://npm.company.internal/", Type: "private", Enabled: true, Scopes: []string{
				"@company",
			}},
		},
		"pypi": {
			"default": {URL: "https://pypi.org/pypi/", SimpleURL: "https://pypi.org/simple/", Type: "public", Enabled: false},
			"internal": {URL: "https://pypi.company.internal/", Type: "private", Enabled: true, PackagePrefixes: []string{
				"company-",
			}},
		},
	}
	return pol
}

func runMCPStdioGate() (bool, string, []string) {
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","method":"ping","id":1}` + "\n")
	var stdout bytes.Buffer

	oldStderr := os.Stderr
	errFile, err := os.CreateTemp("", "pkgsafe-mcp-stderr-*")
	if err != nil {
		return false, "could not capture stderr", []string{err.Error()}
	}
	defer os.Remove(errFile.Name())
	os.Stderr = errFile
	serveErr := mcp.Serve(mcp.ServerConfig{LogLevel: "debug"}, in, &stdout)
	_ = errFile.Close()
	os.Stderr = oldStderr

	stderrBytes, _ := os.ReadFile(errFile.Name())
	var details []string
	if serveErr != nil {
		details = append(details, "MCP server returned error: "+serveErr.Error())
	}
	out := strings.TrimSpace(stdout.String())
	var resp mcp.Response
	if err := json.Unmarshal([]byte(out), &resp); err != nil || resp.JSONRPC != "2.0" {
		details = append(details, "stdout was not a JSON-RPC response")
	}
	if out == "" || !strings.HasPrefix(out, "{") || !strings.HasSuffix(out, "}") {
		details = append(details, "stdout contained non-JSON-RPC content")
	}
	if !strings.Contains(string(stderrBytes), "starting pkgsafe mcp server") {
		details = append(details, "debug log was not observed on stderr")
	}
	if len(details) > 0 {
		return false, "MCP stdio integrity failed", details
	}
	return true, "stdout is JSON-RPC only and debug logs go to stderr", []string{"stderr captured debug output without polluting stdout"}
}

func runInstallInterceptionGate() (bool, string, []string) {
	pol := policy.Default()
	var details []string

	if proceed, _, _ := intercept.CanProceed(nil, types.DecisionWarn, intercept.SafetyFlags{Yes: false}, pol); proceed {
		details = append(details, "WARN proceeded in non-interactive/no-approval mode")
	}
	if proceed, _, _ := intercept.CanProceed(nil, types.DecisionWarn, intercept.SafetyFlags{Yes: true}, pol); !proceed {
		details = append(details, "WARN did not proceed with explicit --yes")
	}
	if proceed, _, _ := intercept.CanProceed(nil, types.DecisionBlock, intercept.SafetyFlags{Yes: true, ForceRiskAccept: false}, pol); proceed {
		details = append(details, "BLOCK proceeded without force-risk-accept")
	}
	_ = os.Setenv("PKGSAFE_REQUESTED_BY", "ai_agent")
	if proceed, _, _ := intercept.CanProceed(nil, types.DecisionWarn, intercept.SafetyFlags{Yes: true}, pol); proceed {
		details = append(details, "AI-agent WARN proceeded by default")
	}
	_ = os.Unsetenv("PKGSAFE_REQUESTED_BY")

	if len(details) > 0 {
		return false, "install interception allowed unsafe install flow", details
	}
	return true, "WARN and BLOCK install enforcement is fail-closed by default", []string{"WARN requires --yes for humans", "BLOCK does not install", "AI-agent WARN does not install by default"}
}

func runMalformedInputGate() (bool, string, []string) {
	tmp, err := os.MkdirTemp("", "pkgsafe-malformed-*")
	if err != nil {
		return false, "could not create malformed input fixtures", []string{err.Error()}
	}
	defer os.RemoveAll(tmp)

	var details []string
	checkNoPanic := func(name string, fn func() error, wantErr bool) {
		defer func() {
			if r := recover(); r != nil {
				details = append(details, name+" panicked: "+fmt.Sprint(r))
			}
		}()
		err := fn()
		if wantErr && err == nil {
			details = append(details, name+" did not fail safely")
		}
	}

	malformedPackage := filepath.Join(tmp, "malformed-package")
	_ = os.MkdirAll(malformedPackage, 0755)
	_ = os.WriteFile(filepath.Join(malformedPackage, "package.json"), []byte(`{"dependencies":`), 0600)
	checkNoPanic("malformed package.json", func() error {
		_, err := npminventory.ScanInventory(malformedPackage)
		return err
	}, false)

	malformedLock := filepath.Join(tmp, "malformed-lock")
	_ = os.MkdirAll(malformedLock, 0755)
	_ = os.WriteFile(filepath.Join(malformedLock, "package-lock.json"), []byte(`{"packages":`), 0600)
	checkNoPanic("malformed package-lock.json", func() error {
		_, err := npminventory.ScanInventory(malformedLock)
		return err
	}, false)

	checkNoPanic("missing lockfile", func() error {
		_, err := anpm.AnalyzeLockfile(filepath.Join(tmp, "missing-package-lock.json"), policy.Default())
		return err
	}, true)

	invalidPolicy := filepath.Join(tmp, "invalid-policy.yaml")
	_ = os.WriteFile(invalidPolicy, []byte("thresholds:\n  block: not-a-number\n"), 0600)
	checkNoPanic("invalid policy", func() error {
		_, err := policy.Load(invalidPolicy)
		return err
	}, true)

	checkNoPanic("unsupported command", func() error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(exe, "__pkgsafe_rollout_unsupported_command__")
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		if !strings.Contains(string(out), "unknown command") {
			return fmt.Errorf("unexpected unsupported command output: %s", strings.TrimSpace(string(out)))
		}
		return err
	}, true)

	if len(details) > 0 {
		return false, "malformed input handling failed", details
	}
	return true, "malformed inputs fail safely without panic", []string{"checked malformed package.json, package-lock.json, missing file, invalid policy, and unsupported command"}
}

func runPackagingGate() (bool, string, []string) {
	var details []string
	if out, err := runRepoCommand("make", "package"); err != nil {
		details = append(details, fmt.Sprintf("make package failed: %v", err))
		if trimmed := strings.TrimSpace(out); trimmed != "" {
			details = append(details, lastLines(trimmed, 12)...)
		}
		return false, "release packaging build failed", details
	}
	details = append(details, "make package passed")

	expected := []string{
		"dist/pkgsafe_linux_amd64",
		"dist/pkgsafe_darwin_amd64",
		"dist/pkgsafe_darwin_arm64",
		"dist/pkgsafe_windows_amd64.exe",
		"dist/checksums.txt",
		"README.md",
		"SECURITY.md",
		"docs/known-limitations.md",
		"default-policy.yaml",
	}
	var missing []string
	for _, path := range expected {
		info, err := os.Stat(path)
		if err != nil {
			missing = append(missing, path)
			continue
		}
		if info.IsDir() {
			missing = append(missing, path+" is a directory")
		}
	}
	if len(missing) > 0 {
		return false, "release packaging artifacts are incomplete", append([]string{"missing or invalid artifacts:"}, missing...)
	}
	details = append(details, expected...)
	return true, "release binaries, checksums, docs, and sample policy exist", details
}

func lastLines(s string, max int) []string {
	lines := strings.Split(s, "\n")
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return lines
}
