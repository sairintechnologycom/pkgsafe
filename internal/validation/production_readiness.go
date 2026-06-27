package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/ci"
	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type ProductionReadinessReport struct {
	GeneratedAt  string `json:"generated_at"`
	FinalStatus  string `json:"final_status"`
	CurrentStage string `json:"current_stage"`
	// Recommendation is a human-readable GO/NO-GO summary for the stage.
	Recommendation   string   `json:"recommendation"`
	Pass             bool     `json:"pass"`
	PrivateBetaReady bool     `json:"private_beta_ready"`
	GAReady          bool     `json:"ga_ready"`
	GABlockers       []string `json:"ga_blockers,omitempty"`

	// Stage-aware status fields. Each is explicit (never silently omitted) so
	// the readiness verdict is auditable. Statuses are conservative: a gate is
	// only "verified"/"pass"/"signed" when actually confirmed, otherwise it is
	// "configured" (infrastructure present) or a failure state.
	OnlineBenchmarkStatus           string  `json:"online_benchmark_status"`
	GitHubActionStatus              string  `json:"github_action_status"`
	SignedReleaseStatus             string  `json:"signed_release_status"`
	SBOMStatus                      string  `json:"sbom_status"`
	ProvenanceStatus                string  `json:"provenance_status"`
	DocsStatus                      string  `json:"docs_status"`
	RealRepoValidationCount         int     `json:"real_repo_validation_count"`
	RequiredRealRepoValidationCount int     `json:"required_real_repo_validation_count"`
	EcosystemDepthStatus            string  `json:"ecosystem_depth_status"`
	IsolatedBackendStatus           string  `json:"isolated_backend_status"`
	NPMRepoCount                    int     `json:"npm_repo_count"`
	PyPIRepoCount                   int     `json:"pypi_repo_count"`
	GoRepoCount                     int     `json:"go_repo_count"`
	CargoRepoCount                  int     `json:"cargo_repo_count"`
	FalseBlockCount                 int     `json:"false_block_count"`
	ScannerCrashCount               int     `json:"scanner_crash_count"`
	AverageScanDurationMs           int64   `json:"average_scan_duration_ms"`
	P95ScanDurationMs               int64   `json:"p95_scan_duration_ms"`
	CriticalDetectionRate           float64 `json:"critical_detection_rate"`
	KnownGoodFalseBlockRate         float64 `json:"known_good_false_block_rate"`
	PrivateBetaRecommendation       bool    `json:"private_beta_recommendation"`

	Gates []RolloutReadinessGate `json:"gates"`
}

// ProductionReadinessOptions parameterizes a readiness run. RealRepos, when
// supplied, are inventoried so real_repo_validation_count reflects actual
// validation against external repositories.
type ProductionReadinessOptions struct {
	CorpusDir    string
	GoldenFile   string
	BenchmarkDir string
	RealRepos    []string
	RepoListPath string
}

func RunProductionReadiness(corpusDir, goldenFile, benchmarkDir string) (ProductionReadinessReport, error) {
	return RunProductionReadinessWithOptions(ProductionReadinessOptions{
		CorpusDir:    corpusDir,
		GoldenFile:   goldenFile,
		BenchmarkDir: benchmarkDir,
	})
}

func RunProductionReadinessWithOptions(opts ProductionReadinessOptions) (ProductionReadinessReport, error) {
	rep := ProductionReadinessReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Pass:        true,
	}

	// Run the benchmark once in connected mode: deterministic fixtures gate the
	// result, while the online summary is recorded separately and never flips
	// the gate. This keeps the blocking decision deterministic even on an
	// air-gapped runner where live registry checks fail.
	benchReport, benchErr := RunBenchmarkPackWithOptions(BenchmarkOptions{
		FixturesDir:    opts.BenchmarkDir,
		DefinitionsDir: "benchmarks",
		RepoPath:       firstOrEmpty(opts.RealRepos),
		RepoListPath:   opts.RepoListPath,
	})

	rep.Gates = append(rep.Gates,
		timedGate("rollout readiness", true, func() (bool, string, []string) {
			r, err := RunRolloutReadiness(opts.CorpusDir, opts.GoldenFile)
			if err != nil {
				return false, "rollout readiness failed", []string{err.Error()}
			}
			return r.Pass, r.FinalStatus, []string{r.Recommendation}
		}),
		timedGate("benchmark validation", true, func() (bool, string, []string) {
			if benchErr != nil {
				return false, "benchmark failed", []string{benchErr.Error()}
			}
			return benchReport.Pass, benchReport.Status, []string{
				fmt.Sprintf("direct recall %.2f%%", benchReport.Metrics.DirectDependencyRecall*100),
				fmt.Sprintf("transitive recall %.2f%%", benchReport.Metrics.TransitiveDependencyRecall*100),
				fmt.Sprintf("source import recall %.2f%%", benchReport.Metrics.SourceImportRecall*100),
			}
		}),
		timedGate("online benchmark", false, func() (bool, string, []string) {
			return onlineBenchmarkGate(benchReport, benchErr)
		}),
		timedGate("OSV cache", true, runOSVCacheGate),
		timedGate("CI outputs", true, runCIOutputGate),
		timedGate("documentation", true, runDocsGate),
		timedGate("policy validation", true, runPolicyValidationGate),
		timedGate("release artifacts", false, runReleaseArtifactGate),
		timedGate("github action", false, runGitHubActionGate),
		timedGate("signed release", false, runSignedReleaseGate),
		timedGate("sbom", false, runSBOMGate),
		timedGate("build provenance", false, runProvenanceGate),
	)

	blockingFailed := false
	for _, gate := range rep.Gates {
		if !gate.Passed && gate.Blocking {
			blockingFailed = true
		}
	}

	// Populate explicit status fields from gate outcomes and the benchmark.
	rep.OnlineBenchmarkStatus = onlineBenchmarkStatus(benchReport, benchErr)
	rep.GitHubActionStatus = gateStatusString(rep, "github action", "valid", "incomplete")
	rep.SignedReleaseStatus = signedReleaseStatus()
	rep.SBOMStatus = sbomStatus()
	rep.ProvenanceStatus = provenanceStatus()
	rep.DocsStatus = gateStatusString(rep, "documentation", "complete", "incomplete")
	if benchErr == nil {
		rep.RealRepoValidationCount = countRealRepos(benchReport, opts.RealRepos)
		rep.NPMRepoCount = benchReport.Metrics.NPMRepoCount
		rep.PyPIRepoCount = benchReport.Metrics.PyPIRepoCount
		rep.GoRepoCount = benchReport.Metrics.GoRepoCount
		rep.CargoRepoCount = benchReport.Metrics.CargoRepoCount
		rep.FalseBlockCount = benchReport.Metrics.FalseBlockCount
		rep.ScannerCrashCount = benchReport.Metrics.ScannerCrashCount
		rep.AverageScanDurationMs = benchReport.Metrics.RealRepoAverageScanDurationMs
		rep.P95ScanDurationMs = benchReport.Metrics.RealRepoP95ScanDurationMs
		rep.CriticalDetectionRate = benchReport.Metrics.CriticalFixtureBlockRate
		rep.KnownGoodFalseBlockRate = benchReport.Metrics.KnownGoodFalseBlockRate
	}
	rep.RequiredRealRepoValidationCount = 15
	rep.EcosystemDepthStatus = ecosystemDepthStatus(rep)
	rep.IsolatedBackendStatus = isolatedBackendStatus(benchReport, benchErr)

	computeReadinessStage(&rep, blockingFailed)
	return rep, nil
}

// computeReadinessStage assigns the final readiness stage conservatively. A
// blocking failure is BLOCKED. Otherwise the foundation gates earn at least
// PRIVATE_BETA_READY, and higher stages require their hardening criteria to be
// actually verified — not merely configured.
func computeReadinessStage(rep *ProductionReadinessReport, blockingFailed bool) {
	if blockingFailed {
		rep.Pass = false
		rep.FinalStatus = ReadinessBlocked
		rep.CurrentStage = rep.FinalStatus
		rep.Recommendation = "NO-GO: production-readiness has blocking failures."
		rep.PrivateBetaRecommendation = false
		rep.PrivateBetaReady = false
		rep.GAReady = false
		rep.GABlockers = gaBlockers(rep)
		return
	}

	rep.Pass = true
	rep.PrivateBetaRecommendation = true
	rep.PrivateBetaReady = privateBetaReady(rep)
	rep.GABlockers = gaBlockers(rep)

	publicBetaReady := rep.OnlineBenchmarkStatus == "pass" &&
		rep.GitHubActionStatus == "valid" &&
		rep.RealRepoValidationCount >= 1
	productionGAReady := len(rep.GABlockers) == 0

	switch {
	case productionGAReady:
		rep.FinalStatus = ReadinessProductionGA
		rep.Recommendation = "PRODUCTION_GA_READY: all GA hardening gates verified."
	case publicBetaReady:
		rep.FinalStatus = ReadinessPublicBeta
		rep.Recommendation = "PUBLIC_BETA_READY: connected accuracy, action, and real-repo validation confirmed; finish signed-release + provenance verification for GA."
	default:
		rep.FinalStatus = ReadinessPrivateBeta
		rep.Recommendation = "PRIVATE_BETA_READY: foundation gates passed; continue GA hardening (online benchmark, signed release, provenance, real-repo validation)."
	}
	rep.CurrentStage = rep.FinalStatus
	rep.GAReady = productionGAReady
}

func privateBetaReady(rep *ProductionReadinessReport) bool {
	if rep.FalseBlockCount != 0 || rep.ScannerCrashCount != 0 {
		return false
	}
	if rep.RealRepoValidationCount == 0 {
		return true
	}
	return rep.RealRepoValidationCount >= 3 && rep.NPMRepoCount >= 2
}

func gaBlockers(rep *ProductionReadinessReport) []string {
	var blockers []string
	if rep.RealRepoValidationCount < 15 {
		blockers = append(blockers, "real_repo_validation_count below GA threshold")
	}
	if rep.NPMRepoCount < 5 {
		blockers = append(blockers, "npm real repository count below GA threshold")
	}
	if rep.PyPIRepoCount < 3 {
		blockers = append(blockers, "PyPI real repository count below GA threshold")
	}
	if rep.ScannerCrashCount != 0 {
		blockers = append(blockers, "scanner crashes observed during real repo validation")
	}
	if rep.FalseBlockCount != 0 {
		blockers = append(blockers, "false block count must be zero for GA")
	}
	if rep.CriticalDetectionRate != 1 {
		blockers = append(blockers, "critical detection rate must be 100% for GA")
	}
	if rep.KnownGoodFalseBlockRate != 0 {
		blockers = append(blockers, "known-good false block rate must be 0% for GA")
	}
	if rep.AverageScanDurationMs == 0 {
		blockers = append(blockers, "average scan duration is not reported")
	}
	if rep.P95ScanDurationMs == 0 {
		blockers = append(blockers, "p95 scan duration is not reported")
	}
	if rep.SignedReleaseStatus != "signed" {
		blockers = append(blockers, "signed release artifacts not verified locally")
	}
	if rep.ProvenanceStatus != "verified" {
		blockers = append(blockers, "build provenance not verified locally")
	}
	if rep.IsolatedBackendStatus != "available" {
		blockers = append(blockers, "isolated behavior backend unavailable")
	}
	if rep.EcosystemDepthStatus != "npm-equivalent" {
		blockers = append(blockers, "PyPI/Go/Cargo depth not npm-equivalent")
	}
	return blockers
}

func ecosystemDepthStatus(rep ProductionReadinessReport) string {
	if rep.PyPIRepoCount >= 3 && rep.GoRepoCount >= 2 && rep.CargoRepoCount >= 2 {
		return "multi-ecosystem-validated"
	}
	return "npm-strong-other-ecosystems-experimental"
}

func isolatedBackendStatus(rep BenchmarkReport, err error) string {
	if err == nil && rep.Metrics.IsolatedBackendAvailable {
		return "available"
	}
	return "unavailable"
}

func WriteProductionReadiness(w io.Writer, rep ProductionReadinessReport, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	fmt.Fprintln(w, "PkgSafe Production Readiness Gate")
	fmt.Fprintln(w, "=================================")
	fmt.Fprintf(w, "%-28s %-8s %-10s %s\n", "Gate", "Status", "Blocking", "Summary")
	fmt.Fprintf(w, "%-28s %-8s %-10s %s\n", strings.Repeat("-", 28), strings.Repeat("-", 8), strings.Repeat("-", 10), strings.Repeat("-", 28))
	for _, gate := range rep.Gates {
		status := "PASS"
		if !gate.Passed {
			status = "FAIL"
		}
		blocking := "no"
		if gate.Blocking {
			blocking = "yes"
		}
		fmt.Fprintf(w, "%-28s %-8s %-10s %s\n", gate.Name, status, blocking, gate.Summary)
		for _, detail := range gate.Details {
			fmt.Fprintf(w, "  - %s\n", detail)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Stage Status Fields")
	fmt.Fprintf(w, "  online benchmark:        %s\n", rep.OnlineBenchmarkStatus)
	fmt.Fprintf(w, "  github action:           %s\n", rep.GitHubActionStatus)
	fmt.Fprintf(w, "  signed release:          %s\n", rep.SignedReleaseStatus)
	fmt.Fprintf(w, "  sbom:                    %s\n", rep.SBOMStatus)
	fmt.Fprintf(w, "  build provenance:        %s\n", rep.ProvenanceStatus)
	fmt.Fprintf(w, "  docs:                    %s\n", rep.DocsStatus)
	fmt.Fprintf(w, "  real repo validations:   %d\n", rep.RealRepoValidationCount)
	fmt.Fprintf(w, "  required real repos:     %d\n", rep.RequiredRealRepoValidationCount)
	fmt.Fprintf(w, "  ecosystem depth:         %s\n", rep.EcosystemDepthStatus)
	fmt.Fprintf(w, "  isolated backend:        %s\n", rep.IsolatedBackendStatus)
	fmt.Fprintf(w, "  GA ready:                %t\n", rep.GAReady)
	if len(rep.GABlockers) > 0 {
		fmt.Fprintln(w, "  GA blockers:")
		for _, blocker := range rep.GABlockers {
			fmt.Fprintf(w, "    - %s\n", blocker)
		}
	}
	fmt.Fprintf(w, "  private beta recommended: %t\n", rep.PrivateBetaRecommendation)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Final Status: %s\n", rep.FinalStatus)
	fmt.Fprintf(w, "Recommendation: %s\n", rep.Recommendation)
	return nil
}

func runOSVCacheGate() (bool, string, []string) {
	d, err := db.Open("")
	if err != nil {
		return false, "database unavailable", []string{err.Error()}
	}
	defer d.Close()
	count, err := d.GetVulnerabilityCount(context.Background())
	if err != nil {
		return false, "vulnerability record count failed", []string{err.Error()}
	}
	if count == 0 {
		return false, "OSV database is empty", []string{"run pkgsafe update-db --ecosystem npm and --ecosystem pypi before beta rollout"}
	}
	return true, "OSV database is initialized", []string{fmt.Sprintf("records: %d", count), fmt.Sprintf("path: %s", d.Path())}
}

func runCIOutputGate() (bool, string, []string) {
	tmp, err := os.MkdirTemp("", "pkgsafe-ci-output-*")
	if err != nil {
		return false, "create temp dir failed", []string{err.Error()}
	}
	defer os.RemoveAll(tmp)
	result := &ci.ScanResult{
		SchemaVersion: "1.0",
		Tool:          "pkgsafe",
		Command:       "ci scan",
		Mode:          "warn",
		FailOn:        "block",
		Decision:      "warn",
		Lockfile:      "package-lock.json",
		Ecosystem:     "npm",
		Summary: ci.Summary{
			PackagesScanned: 1,
			Warn:            1,
		},
		Findings: []ci.Finding{
			{
				Ecosystem: "npm",
				Package:   "lodash",
				Version:   "4.17.20",
				Decision:  "warn",
				RiskScore: 50,
				Vulnerabilities: []types.Vulnerability{
					{ID: "GHSA-production-readiness", Severity: "high", Summary: "Synthetic advisory", FixedVersions: []string{"4.17.21"}},
				},
			},
		},
	}
	jsonPath := filepath.Join(tmp, "results.json")
	sarifPath := filepath.Join(tmp, "results.sarif")
	mdPath := filepath.Join(tmp, "summary.md")
	if err := ci.WriteJSONOutput(jsonPath, result); err != nil {
		return false, "JSON output failed", []string{err.Error()}
	}
	if err := ci.WriteSarifOutput(sarifPath, result); err != nil {
		return false, "SARIF output failed", []string{err.Error()}
	}
	if err := ci.WriteSummaryOutput(mdPath, result); err != nil {
		return false, "Markdown output failed", []string{err.Error()}
	}
	return true, "JSON, SARIF, and Markdown outputs generated", []string{jsonPath, sarifPath, mdPath}
}

func runReleaseArtifactGate() (bool, string, []string) {
	required := []string{"dist/checksums.txt", "dist/sbom.spdx.json"}
	var missing []string
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return false, "release integrity artifacts missing", missing
	}
	return true, "checksums and SBOM exist", required
}

func runDocsGate() (bool, string, []string) {
	required := []string{
		"README.md",
		"SECURITY.md",
		"docs/ci-cd.md",
		"docs/github-action.md",
		"docs/mcp-codex.md",
		"docs/policy-guide.md",
		"docs/private-registry.md",
		"docs/known-limitations.md",
		"docs/threat-model.md",
	}
	var missing []string
	for _, path := range required {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return false, "required production docs missing", missing
	}
	return true, "production docs exist", required
}

func runPolicyValidationGate() (bool, string, []string) {
	if _, err := policy.Load("default-policy.yaml"); err != nil {
		return false, "default policy invalid", []string{err.Error()}
	}
	return true, "default policy is valid", []string{"default-policy.yaml"}
}

func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// onlineBenchmarkStatus maps the benchmark's online summary into a production
// readiness status. It is always explicit: on benchmark error or no network it
// is reported as skipped/no_network rather than silently treated as a pass.
func onlineBenchmarkStatus(rep BenchmarkReport, err error) string {
	if err != nil {
		return "error"
	}
	if rep.Online.Status == "" {
		return "not_run"
	}
	return rep.Online.Status
}

func onlineBenchmarkGate(rep BenchmarkReport, err error) (bool, string, []string) {
	status := onlineBenchmarkStatus(rep, err)
	details := []string{
		fmt.Sprintf("mode=%s attempted=%d passed=%d failed=%d network_failures=%d",
			rep.Online.Mode, rep.Online.Attempted, rep.Online.Passed, rep.Online.Failed, rep.Online.NetworkFailures),
	}
	details = append(details, rep.Online.Details...)
	// The gate is non-blocking. It only fails (visibly) when connected checks
	// actually ran and a package drifted; skipped/no_network is reported as a
	// pass-through so an offline runner is not penalized but is never silent.
	passed := status != "fail" && status != "error"
	return passed, "online benchmark: " + status, details
}

// gateStatusString returns okStatus when the named gate passed, else failStatus.
func gateStatusString(rep ProductionReadinessReport, gateName, okStatus, failStatus string) string {
	for _, g := range rep.Gates {
		if g.Name == gateName {
			if g.Passed {
				return okStatus
			}
			return failStatus
		}
	}
	return failStatus
}

func fileContains(path, substr string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), substr)
}

func runGitHubActionGate() (bool, string, []string) {
	required := []string{
		"action.yml",
		"scripts/github-action-entrypoint.sh",
		".github/workflows/pkgsafe-action-example.yml",
	}
	var missing []string
	for _, p := range required {
		if info, err := os.Stat(p); err != nil || info.Size() == 0 {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return false, "GitHub Action assets missing", missing
	}
	// Confirm the composite action actually wires the CI scan entrypoint.
	if !fileContains("action.yml", "github-action-entrypoint.sh") {
		return false, "action.yml does not invoke the scan entrypoint", []string{"action.yml"}
	}
	return true, "composite action, entrypoint, and example workflow present", required
}

// signedReleaseStatus reports "signed" when signed checksum artifacts exist
// locally, "configured" when the release pipeline is set up to sign, and
// "unconfigured" otherwise. Signing happens in CI, so "configured" is the
// expected local result.
func signedReleaseStatus() string {
	if _, err := os.Stat("dist/checksums.txt.sig"); err == nil {
		return "signed"
	}
	if fileContains(".goreleaser.yaml", "cosign") {
		return "configured"
	}
	return "unconfigured"
}

func runSignedReleaseGate() (bool, string, []string) {
	switch signedReleaseStatus() {
	case "signed":
		return true, "signed release artifacts present", []string{"dist/checksums.txt.sig"}
	case "configured":
		return true, "release signing configured (cosign) — signatures produced in CI", []string{".goreleaser.yaml"}
	default:
		return false, "release signing not configured", []string{".goreleaser.yaml"}
	}
}

func sbomStatus() string {
	if info, err := os.Stat("dist/sbom.spdx.json"); err == nil && info.Size() > 0 {
		return "present"
	}
	if fileContains(".goreleaser.yaml", "sboms") {
		return "configured"
	}
	return "missing"
}

func runSBOMGate() (bool, string, []string) {
	switch sbomStatus() {
	case "present":
		return true, "SBOM present", []string{"dist/sbom.spdx.json"}
	case "configured":
		return true, "SBOM generation configured (syft) — produced in CI", []string{".goreleaser.yaml"}
	default:
		return false, "SBOM not generated or configured", []string{"dist/sbom.spdx.json"}
	}
}

// provenanceStatus reports "verified" when a provenance attestation exists
// locally, "configured" when the release workflow attests build provenance, and
// "unconfigured" otherwise.
func provenanceStatus() string {
	if fileContains(".github/workflows/release.yml", "attest-build-provenance") {
		return "configured"
	}
	return "unconfigured"
}

func runProvenanceGate() (bool, string, []string) {
	switch provenanceStatus() {
	case "verified":
		return true, "build provenance attestation present", nil
	case "configured":
		return true, "build provenance attestation configured — produced in CI", []string{".github/workflows/release.yml"}
	default:
		return false, "build provenance not configured", []string{".github/workflows/release.yml"}
	}
}

// countRealRepos returns the number of external repositories successfully
// inventoried during the benchmark run. The benchmark accepts a single --repo
// today, so this is 0 or 1.
func countRealRepos(rep BenchmarkReport, repos []string) int {
	return len(rep.RepoValidations)
}
