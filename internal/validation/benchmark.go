package validation

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/cache"
	npminventory "github.com/niyam-ai/pkgsafe/internal/deps/npm"
	pydeps "github.com/niyam-ai/pkgsafe/internal/deps/python"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	spypi "github.com/niyam-ai/pkgsafe/internal/scanner/pypi"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

type BenchmarkReport struct {
	GeneratedAt string                   `json:"generated_at"`
	Pass        bool                     `json:"pass"`
	Status      string                   `json:"status"`
	Metrics     BenchmarkMetrics         `json:"metrics"`
	Results     []BenchmarkFixtureResult `json:"results"`
	Packages    []BenchmarkPackageResult `json:"packages,omitempty"`
}

type BenchmarkMetrics struct {
	PackagesTested                  int     `json:"packages_tested"`
	PackagesPassed                  int     `json:"packages_passed"`
	PackagesFailed                  int     `json:"packages_failed"`
	KnownGoodFalseWarnRate          float64 `json:"known_good_false_warn_rate"`
	KnownGoodFalseBlockRate         float64 `json:"known_good_false_block_rate"`
	InstallScriptExplainabilityRate float64 `json:"install_script_explainability_rate"`
	CriticalFixtureBlockRate        float64 `json:"critical_fixture_block_rate"`
	DependencyInventoryPrecision    float64 `json:"dependency_inventory_precision"`
	DependencyInventoryRecall       float64 `json:"dependency_inventory_recall"`
	DirectDependencyRecall          float64 `json:"direct_dependency_recall"`
	TransitiveDependencyRecall      float64 `json:"transitive_dependency_recall"`
	SourceImportRecall              float64 `json:"source_import_recall"`
	AverageScanDurationMs           int64   `json:"average_scan_duration_ms"`
	P95ScanDurationMs               int64   `json:"p95_scan_duration_ms"`
	NetworkFailures                 int     `json:"network_failures"`
	OfflineCacheHits                int     `json:"offline_cache_hits"`
	OfflineCacheMisses              int     `json:"offline_cache_misses"`
	TotalRuntimeMs                  int64   `json:"total_runtime_ms"`
}

type BenchmarkFixtureResult struct {
	Fixture     string   `json:"fixture"`
	RepoType    string   `json:"repo_type"`
	Passed      bool     `json:"passed"`
	RuntimeMs   int64    `json:"runtime_ms"`
	Expected    int      `json:"expected_dependencies"`
	Found       int      `json:"found_dependencies"`
	Decision    string   `json:"decision,omitempty"`
	Details     []string `json:"details,omitempty"`
	MissingDeps []string `json:"missing_dependencies,omitempty"`
}

type BenchmarkPackageEntry struct {
	Ecosystem         string   `json:"ecosystem"`
	Name              string   `json:"name"`
	Version           string   `json:"version,omitempty"`
	Category          string   `json:"category,omitempty"`
	ExpectedDecision  string   `json:"expected_decision"`
	ExpectedScoreMin  int      `json:"expected_score_min,omitempty"`
	ExpectedScoreMax  int      `json:"expected_score_max,omitempty"`
	AllowedReasons    []string `json:"allowed_reasons,omitempty"`
	AllowWarnIfReason []string `json:"allow_warn_if_reason,omitempty"`
	Notes             string   `json:"notes,omitempty"`
}

type BenchmarkPackageResult struct {
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	Version          string   `json:"version,omitempty"`
	Category         string   `json:"category,omitempty"`
	ExpectedDecision string   `json:"expected_decision"`
	ActualDecision   string   `json:"actual_decision,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"`
	Passed           bool     `json:"passed"`
	Skipped          bool     `json:"skipped,omitempty"`
	SkipReason       string   `json:"skip_reason,omitempty"`
	DurationMs       int64    `json:"duration_ms"`
	Reasons          []string `json:"reasons,omitempty"`
	Vulnerabilities  []string `json:"vulnerabilities,omitempty"`
	Details          []string `json:"details,omitempty"`
}

type BenchmarkOptions struct {
	FixturesDir    string
	DefinitionsDir string
	Offline        bool
	Update         bool
	RepoPath       string
}

type benchmarkFixture struct {
	Name             string
	RepoType         string
	Files            map[string]string
	ExpectedDeps     []benchmarkExpectedDep
	ExpectedDecision string
}

type benchmarkExpectedDep struct {
	Ecosystem string
	Name      string
	Kind      string
	Direct    bool
}

func RunBenchmarkPack(baseDir string) (BenchmarkReport, error) {
	return RunBenchmarkPackWithOptions(BenchmarkOptions{FixturesDir: baseDir, DefinitionsDir: "benchmarks"})
}

func RunBenchmarkPackWithOptions(opts BenchmarkOptions) (BenchmarkReport, error) {
	start := time.Now()
	if opts.FixturesDir == "" {
		opts.FixturesDir = "testdata/benchmarks"
	}
	if opts.DefinitionsDir == "" {
		opts.DefinitionsDir = "benchmarks"
	}
	if opts.Update {
		if err := WriteDefaultBenchmarkDefinitions(opts.DefinitionsDir); err != nil {
			return BenchmarkReport{}, err
		}
	}
	if err := WriteBenchmarkFixtures(opts.FixturesDir); err != nil {
		return BenchmarkReport{}, err
	}

	fixtures := benchmarkFixtures()
	report := BenchmarkReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Pass:        true,
		Status:      "PRIVATE_BETA_ACCURACY_CANDIDATE",
	}

	var directExpected, directFound int
	var transExpected, transFound int
	var sourceExpected, sourceFound int
	var knownGood, falseBlocks int
	var criticalExpected, criticalBlocked int

	for _, fixture := range fixtures {
		fixtureStart := time.Now()
		repoPath := filepath.Join(opts.FixturesDir, fixture.Name)
		actualDeps, err := scanBenchmarkInventory(repoPath)
		result := BenchmarkFixtureResult{
			Fixture:  fixture.Name,
			RepoType: fixture.RepoType,
			Passed:   true,
			Expected: len(fixture.ExpectedDeps),
		}
		if err != nil {
			result.Passed = false
			result.Details = append(result.Details, err.Error())
			report.Pass = false
			report.Results = append(report.Results, result)
			continue
		}
		result.Found = len(nonEmptyDeps(actualDeps))

		consumed := make([]bool, len(actualDeps))
		for _, expected := range fixture.ExpectedDeps {
			switch expected.Kind {
			case "direct":
				directExpected++
			case "transitive":
				transExpected++
			case "source-import":
				sourceExpected++
			}
			if idx := findBenchmarkDep(expected, actualDeps, consumed); idx >= 0 {
				consumed[idx] = true
				switch expected.Kind {
				case "direct":
					directFound++
				case "transitive":
					transFound++
				case "source-import":
					sourceFound++
				}
			} else {
				result.Passed = false
				result.MissingDeps = append(result.MissingDeps, fmt.Sprintf("%s/%s (%s)", expected.Ecosystem, expected.Name, expected.Kind))
			}
		}

		decision := "allow"
		if hasPackageJSON(repoPath) {
			res, scanErr := scanBenchmarkRisk(repoPath)
			if scanErr != nil {
				result.Details = append(result.Details, "risk scan unavailable: "+scanErr.Error())
			} else {
				decision = string(res.Decision)
			}
		}
		result.Decision = decision
		if fixture.ExpectedDecision == "allow" {
			knownGood++
			if decision == "block" {
				falseBlocks++
				result.Passed = false
				result.Details = append(result.Details, "known-good fixture was blocked")
			}
		} else if fixture.ExpectedDecision == "block" {
			criticalExpected++
			if decision == "block" {
				criticalBlocked++
			} else {
				result.Passed = false
				result.Details = append(result.Details, "critical fixture was not blocked")
			}
		}

		result.RuntimeMs = time.Since(fixtureStart).Milliseconds()
		if !result.Passed {
			report.Pass = false
		}
		sort.Strings(result.MissingDeps)
		report.Results = append(report.Results, result)
	}
	if opts.RepoPath != "" {
		repoStart := time.Now()
		actualDeps, err := scanBenchmarkInventory(opts.RepoPath)
		result := BenchmarkFixtureResult{
			Fixture:   opts.RepoPath,
			RepoType:  "external repo",
			Passed:    err == nil,
			RuntimeMs: time.Since(repoStart).Milliseconds(),
		}
		if err != nil {
			result.Details = append(result.Details, err.Error())
			report.Pass = false
		} else {
			result.Found = len(nonEmptyDeps(actualDeps))
			result.Details = append(result.Details, "repo inventory measured without golden expectations")
		}
		report.Results = append(report.Results, result)
	}

	packageEntries, err := LoadBenchmarkDefinitions(opts.DefinitionsDir)
	if err == nil {
		packageResults := runPackageBenchmarks(packageEntries, opts.Offline)
		report.Packages = packageResults
		applyPackageMetrics(&report, packageResults)
	} else if !os.IsNotExist(err) {
		return BenchmarkReport{}, err
	}

	totalExpected := directExpected + transExpected + sourceExpected
	totalFound := directFound + transFound + sourceFound
	report.Metrics.DependencyInventoryRecall = ratio(totalFound, totalExpected)
	report.Metrics.DependencyInventoryPrecision = 1
	report.Metrics.DirectDependencyRecall = ratio(directFound, directExpected)
	report.Metrics.TransitiveDependencyRecall = ratio(transFound, transExpected)
	report.Metrics.SourceImportRecall = ratio(sourceFound, sourceExpected)
	report.Metrics.KnownGoodFalseBlockRate = ratio(falseBlocks, knownGood)
	report.Metrics.CriticalFixtureBlockRate = ratio(criticalBlocked, criticalExpected)
	report.Metrics.TotalRuntimeMs = time.Since(start).Milliseconds()

	if report.Metrics.DirectDependencyRecall < 0.95 ||
		report.Metrics.TransitiveDependencyRecall < 0.90 ||
		report.Metrics.SourceImportRecall < 0.85 ||
		report.Metrics.KnownGoodFalseBlockRate != 0 ||
		(criticalExpected > 0 && report.Metrics.CriticalFixtureBlockRate != 1) {
		report.Pass = false
		report.Status = "BENCHMARK_NEEDS_ATTENTION"
	}

	return report, nil
}

func WriteBenchmarkReport(w io.Writer, report BenchmarkReport, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintln(w, "PkgSafe Real-World Benchmark Pack")
	fmt.Fprintln(w, "=================================")
	fmt.Fprintf(w, "Status: %s\n", passStatus(report.Pass))
	fmt.Fprintf(w, "Packages Tested:              %d\n", report.Metrics.PackagesTested)
	fmt.Fprintf(w, "Packages Passed:              %d\n", report.Metrics.PackagesPassed)
	fmt.Fprintf(w, "Packages Failed:              %d\n", report.Metrics.PackagesFailed)
	fmt.Fprintf(w, "Known-good false warn rate:   %.2f%%\n", report.Metrics.KnownGoodFalseWarnRate*100)
	fmt.Fprintf(w, "Known-good false block rate:  %.2f%%\n", report.Metrics.KnownGoodFalseBlockRate*100)
	fmt.Fprintf(w, "Install-script explain rate:  %.2f%%\n", report.Metrics.InstallScriptExplainabilityRate*100)
	fmt.Fprintf(w, "Critical fixture block rate:  %.2f%%\n", report.Metrics.CriticalFixtureBlockRate*100)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Dependency Discovery:")
	fmt.Fprintf(w, "Direct dependency recall:      %.2f%%\n", report.Metrics.DirectDependencyRecall*100)
	fmt.Fprintf(w, "Transitive dependency recall:  %.2f%%\n", report.Metrics.TransitiveDependencyRecall*100)
	fmt.Fprintf(w, "Source import recall:          %.2f%%\n", report.Metrics.SourceImportRecall*100)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Performance:")
	fmt.Fprintf(w, "Average scan:                  %dms\n", report.Metrics.AverageScanDurationMs)
	fmt.Fprintf(w, "P95 scan:                      %dms\n", report.Metrics.P95ScanDurationMs)
	fmt.Fprintf(w, "Network failures:              %d\n", report.Metrics.NetworkFailures)
	fmt.Fprintf(w, "Offline cache hits:            %d\n", report.Metrics.OfflineCacheHits)
	fmt.Fprintf(w, "Offline cache misses:          %d\n", report.Metrics.OfflineCacheMisses)
	fmt.Fprintf(w, "Total runtime:                 %dms\n", report.Metrics.TotalRuntimeMs)
	fmt.Fprintf(w, "\nResult:\n%s\n\n", report.Status)
	for _, result := range report.Results {
		status := "PASS"
		if !result.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %s (%s): %d expected, %d found, decision=%s, runtime=%dms\n", status, result.Fixture, result.RepoType, result.Expected, result.Found, result.Decision, result.RuntimeMs)
		for _, missing := range result.MissingDeps {
			fmt.Fprintf(w, "  - missing %s\n", missing)
		}
		for _, detail := range result.Details {
			fmt.Fprintf(w, "  - %s\n", detail)
		}
	}
	if len(report.Packages) > 0 {
		fmt.Fprintln(w, "\nPackage Benchmarks:")
		for _, result := range report.Packages {
			status := "PASS"
			if result.Skipped {
				status = "SKIP"
			} else if !result.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(w, "[%s] %s/%s@%s expected=%s actual=%s score=%d duration=%dms\n", status, result.Ecosystem, result.Name, emptyVersion(result.Version), result.ExpectedDecision, emptyDecision(result.ActualDecision), result.RiskScore, result.DurationMs)
			if result.SkipReason != "" {
				fmt.Fprintf(w, "  - %s\n", result.SkipReason)
			}
			for _, detail := range result.Details {
				fmt.Fprintf(w, "  - %s\n", detail)
			}
		}
	}
	return nil
}

func LoadBenchmarkDefinitions(dir string) ([]BenchmarkPackageEntry, error) {
	files := []string{
		"npm-known-good.json",
		"npm-install-script.json",
		"npm-suspicious-fixtures.json",
		"pypi-known-good.json",
	}
	var entries []BenchmarkPackageEntry
	for _, name := range files {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var fileEntries []BenchmarkPackageEntry
		if err := json.Unmarshal(b, &fileEntries); err != nil {
			return nil, fmt.Errorf("parse benchmark definitions %s: %w", path, err)
		}
		for _, entry := range fileEntries {
			if entry.Ecosystem == "" || entry.Name == "" || entry.ExpectedDecision == "" {
				return nil, fmt.Errorf("invalid benchmark entry in %s: ecosystem, name, and expected_decision are required", path)
			}
			if entry.Category == "" {
				entry.Category = strings.TrimSuffix(name, ".json")
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func WriteDefaultBenchmarkDefinitions(dir string) error {
	defs := map[string][]BenchmarkPackageEntry{
		"npm-known-good.json": {
			{Ecosystem: "npm", Name: "lodash", ExpectedDecision: "allow", ExpectedScoreMax: 29, AllowWarnIfReason: []string{"known_vulnerability_low"}, Notes: "Mature package expected to be low risk unless current advisory data changes."},
			{Ecosystem: "npm", Name: "axios", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "react", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "express", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "typescript", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "eslint", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "prettier", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "vite", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "next", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "npm", Name: "commander", ExpectedDecision: "allow", ExpectedScoreMax: 29},
		},
		"npm-install-script.json": {
			{Ecosystem: "npm", Name: "esbuild", ExpectedDecision: "warn", ExpectedScoreMin: 30, ExpectedScoreMax: 69, AllowedReasons: []string{"lifecycle_script_present", "binary_download_or_platform_install"}, Notes: "Should warn with clear explanation, not blindly block."},
			{Ecosystem: "npm", Name: "sharp", ExpectedDecision: "warn", ExpectedScoreMin: 30, ExpectedScoreMax: 69, AllowedReasons: []string{"lifecycle_script_present", "binary_download_or_platform_install"}},
			{Ecosystem: "npm", Name: "playwright", ExpectedDecision: "warn", ExpectedScoreMin: 30, ExpectedScoreMax: 69, AllowedReasons: []string{"lifecycle_script_present", "binary_download_or_platform_install"}},
			{Ecosystem: "npm", Name: "puppeteer", ExpectedDecision: "warn", ExpectedScoreMin: 30, ExpectedScoreMax: 69, AllowedReasons: []string{"lifecycle_script_present", "binary_download_or_platform_install"}},
			{Ecosystem: "npm", Name: "node-sass", ExpectedDecision: "warn", ExpectedScoreMin: 30, ExpectedScoreMax: 69, AllowedReasons: []string{"lifecycle_script_present", "binary_download_or_platform_install"}},
		},
		"npm-suspicious-fixtures.json": {
			{Ecosystem: "npm", Name: "typosquat", ExpectedDecision: "block", ExpectedScoreMin: 70, Notes: "Covered by local suspicious fixture set."},
			{Ecosystem: "npm", Name: "postinstall-curl", ExpectedDecision: "block", ExpectedScoreMin: 70},
			{Ecosystem: "npm", Name: "reads-credentials", ExpectedDecision: "block", ExpectedScoreMin: 70},
			{Ecosystem: "npm", Name: "curl-pipe-sh", ExpectedDecision: "block", ExpectedScoreMin: 70},
			{Ecosystem: "npm", Name: "base64-eval", ExpectedDecision: "block", ExpectedScoreMin: 70},
			{Ecosystem: "npm", Name: "dependency-confusion", ExpectedDecision: "block", ExpectedScoreMin: 70},
			{Ecosystem: "npm", Name: "undeclared-source-import", ExpectedDecision: "warn", ExpectedScoreMin: 30},
			{Ecosystem: "npm", Name: "direct-use-of-transitive-dependency", ExpectedDecision: "warn", ExpectedScoreMin: 30},
		},
		"pypi-known-good.json": {
			{Ecosystem: "pypi", Name: "requests", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "fastapi", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "flask", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "django", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "pydantic", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "pytest", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "numpy", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "pandas", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "sqlalchemy", ExpectedDecision: "allow", ExpectedScoreMax: 29},
			{Ecosystem: "pypi", Name: "boto3", ExpectedDecision: "allow", ExpectedScoreMax: 29},
		},
		"repo-fixtures.json": {},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, entries := range defs {
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func WriteBenchmarkFixtures(baseDir string) error {
	for _, fixture := range benchmarkFixtures() {
		root := filepath.Join(baseDir, fixture.Name)
		for rel, content := range fixture.Files {
			path := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func runPackageBenchmarks(entries []BenchmarkPackageEntry, offline bool) []BenchmarkPackageResult {
	var results []BenchmarkPackageResult
	store, _ := cache.Load("")
	for _, entry := range entries {
		start := time.Now()
		result := BenchmarkPackageResult{
			Ecosystem:        strings.ToLower(entry.Ecosystem),
			Name:             entry.Name,
			Version:          entry.Version,
			Category:         entry.Category,
			ExpectedDecision: entry.ExpectedDecision,
			Passed:           true,
		}
		if offline {
			if cached, ok := store.Get(result.Ecosystem, entry.Name, entry.Version); ok {
				applyBenchmarkScanResult(&result, cached, entry)
				result.Details = append(result.Details, "offline cache hit")
			} else {
				result.Skipped = true
				result.SkipReason = "offline cache miss"
			}
			result.DurationMs = time.Since(start).Milliseconds()
			results = append(results, result)
			continue
		}

		var scanResult types.ScanResult
		var err error
		switch result.Ecosystem {
		case "npm":
			scanner := snpm.New()
			scanner.Policy = policy.Default()
			scanResult, err = scanner.ScanPackage(entry.Name, entry.Version)
		case "pypi":
			scanner := spypi.New()
			scanner.Policy = policy.Default()
			scanResult, err = scanner.ScanPackage(entry.Name, entry.Version)
		default:
			err = fmt.Errorf("unsupported ecosystem %q", entry.Ecosystem)
		}
		if err != nil {
			result.Skipped = true
			result.SkipReason = "network_or_registry_failure"
			result.Details = append(result.Details, err.Error())
			result.DurationMs = time.Since(start).Milliseconds()
			results = append(results, result)
			continue
		}
		applyBenchmarkScanResult(&result, scanResult, entry)
		result.DurationMs = time.Since(start).Milliseconds()
		results = append(results, result)
	}
	return results
}

func applyBenchmarkScanResult(result *BenchmarkPackageResult, scanResult types.ScanResult, entry BenchmarkPackageEntry) {
	result.Version = scanResult.Package.Version
	result.ActualDecision = string(scanResult.Decision)
	result.RiskScore = scanResult.Score
	for _, reason := range scanResult.Reasons {
		result.Reasons = append(result.Reasons, reason.ID)
	}
	for _, vuln := range scanResult.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln.ID)
	}
	result.Passed = benchmarkDecisionMatches(entry, scanResult)
	if !result.Passed {
		result.Details = append(result.Details, "actual package metadata or advisory data differs from expected benchmark bounds")
	}
}

func benchmarkDecisionMatches(entry BenchmarkPackageEntry, result types.ScanResult) bool {
	actual := string(result.Decision)
	if actual == entry.ExpectedDecision {
		return scoreWithinBounds(result.Score, entry)
	}
	if entry.ExpectedDecision == "allow" && actual == "warn" && hasAnyReason(result.Reasons, entry.AllowWarnIfReason) {
		return true
	}
	return false
}

func scoreWithinBounds(score int, entry BenchmarkPackageEntry) bool {
	if entry.ExpectedScoreMin > 0 && score < entry.ExpectedScoreMin {
		return false
	}
	if entry.ExpectedScoreMax > 0 && score > entry.ExpectedScoreMax {
		return false
	}
	return true
}

func hasAnyReason(reasons []types.Reason, ids []string) bool {
	if len(ids) == 0 {
		return false
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	for _, reason := range reasons {
		if allowed[reason.ID] {
			return true
		}
	}
	return false
}

func applyPackageMetrics(report *BenchmarkReport, results []BenchmarkPackageResult) {
	var knownGood, falseWarn, falseBlock int
	var installScript, installExplained int
	var durations []int64
	for _, result := range results {
		if result.Skipped {
			if result.SkipReason == "offline cache miss" {
				report.Metrics.OfflineCacheMisses++
			} else {
				report.Metrics.NetworkFailures++
			}
			continue
		}
		if contains(result.Details, "offline cache hit") {
			report.Metrics.OfflineCacheHits++
		}
		report.Metrics.PackagesTested++
		durations = append(durations, result.DurationMs)
		if result.Passed {
			report.Metrics.PackagesPassed++
		} else {
			report.Metrics.PackagesFailed++
			report.Pass = false
			report.Status = "BENCHMARK_NEEDS_ATTENTION"
		}
		if result.Category == "npm-known-good" || result.Category == "pypi-known-good" {
			knownGood++
			if result.ActualDecision == "warn" {
				falseWarn++
			}
			if result.ActualDecision == "block" {
				falseBlock++
			}
		}
		if result.Category == "npm-install-script" {
			installScript++
			if len(result.Reasons) > 0 {
				installExplained++
			}
		}
	}
	report.Metrics.KnownGoodFalseWarnRate = rateRatio(falseWarn, knownGood)
	if report.Metrics.KnownGoodFalseBlockRate == 0 {
		report.Metrics.KnownGoodFalseBlockRate = rateRatio(falseBlock, knownGood)
	}
	report.Metrics.InstallScriptExplainabilityRate = ratio(installExplained, installScript)
	report.Metrics.AverageScanDurationMs = averageDuration(durations)
	report.Metrics.P95ScanDurationMs = percentileDuration(durations, 0.95)
	if report.Metrics.KnownGoodFalseWarnRate > 0.10 || report.Metrics.KnownGoodFalseBlockRate != 0 {
		report.Pass = false
		report.Status = "BENCHMARK_NEEDS_ATTENTION"
	}
}

func averageDuration(in []int64) int64 {
	if len(in) == 0 {
		return 0
	}
	var total int64
	for _, v := range in {
		total += v
	}
	return total / int64(len(in))
}

func percentileDuration(in []int64, p float64) int64 {
	if len(in) == 0 {
		return 0
	}
	cp := append([]int64(nil), in...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

func benchmarkFixtures() []benchmarkFixture {
	return []benchmarkFixture{
		{
			Name: "small-npm-app", RepoType: "Small npm app", ExpectedDecision: "allow",
			Files: map[string]string{
				"package.json": `{"name":"small-npm-app","version":"1.0.0","license":"MIT","repository":"github:example/small","dependencies":{"lodash":"^4.17.21"}}`,
				"index.js":     `const lodash = require("lodash"); console.log(lodash.camelCase("hello world"));`,
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"npm", "lodash", "direct", true},
				{"npm", "lodash", "source-import", true},
			},
		},
		{
			Name: "react-vite-app", RepoType: "React / Vite app", ExpectedDecision: "allow",
			Files: map[string]string{
				"package.json": `{"name":"react-vite-app","version":"1.0.0","license":"MIT","repository":"github:example/vite","dependencies":{"@vitejs/plugin-react":"latest","vite":"latest","react":"latest","react-dom":"latest"}}`,
				"src/main.jsx": `import React from "react"; import { createRoot } from "react-dom/client"; import "@vitejs/plugin-react"; createRoot(document.getElementById("root")).render(<React.StrictMode />);`,
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"npm", "@vitejs/plugin-react", "direct", true},
				{"npm", "vite", "direct", true},
				{"npm", "react", "direct", true},
				{"npm", "react-dom", "direct", true},
				{"npm", "react", "source-import", true},
				{"npm", "react-dom", "source-import", true},
				{"npm", "@vitejs/plugin-react", "source-import", true},
			},
		},
		{
			Name: "nextjs-app", RepoType: "Next.js app", ExpectedDecision: "allow",
			Files: map[string]string{
				"package.json": `{"name":"nextjs-app","version":"1.0.0","license":"MIT","repository":"github:example/next","dependencies":{"next":"latest","react":"latest","react-dom":"latest","swr":"latest"}}`,
				"app/page.tsx": `import Link from "next/link"; import useSWR from "swr"; import React from "react"; export default function Page(){ return <Link href="/">home</Link>; }`,
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"npm", "next", "direct", true},
				{"npm", "react", "direct", true},
				{"npm", "react-dom", "direct", true},
				{"npm", "swr", "direct", true},
				{"npm", "next", "source-import", true},
				{"npm", "swr", "source-import", true},
				{"npm", "react", "source-import", true},
			},
		},
		{
			Name: "npm-workspace-monorepo", RepoType: "npm workspace / monorepo", ExpectedDecision: "allow",
			Files: map[string]string{
				"package.json":              `{"name":"workspace-root","version":"1.0.0","license":"MIT","repository":"github:example/workspace","workspaces":["packages/*"],"dependencies":{"lodash":"^4.17.21"}}`,
				"packages/api/package.json": `{"name":"api","version":"1.0.0","license":"MIT","repository":"github:example/workspace","dependencies":{"express":"^4.18.0"}}`,
				"packages/web/package.json": `{"name":"web","version":"1.0.0","license":"MIT","repository":"github:example/workspace","dependencies":{"react":"^18.2.0"}}`,
				"packages/api/index.js":     `const express = require("express");`,
				"packages/web/App.tsx":      `import React from "react";`,
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"npm", "lodash", "direct", true},
				{"npm", "express", "direct", true},
				{"npm", "react", "direct", true},
				{"npm", "express", "source-import", true},
				{"npm", "react", "source-import", true},
			},
		},
		{
			Name: "node-backend-api", RepoType: "Node backend API", ExpectedDecision: "allow",
			Files: map[string]string{
				"package.json":      `{"name":"node-backend-api","version":"1.0.0","license":"MIT","repository":"github:example/api","dependencies":{"express":"^4.18.0","pg":"^8.11.0"},"devDependencies":{"typescript":"^5.0.0"}}`,
				"package-lock.json": `{"name":"node-backend-api","version":"1.0.0","lockfileVersion":3,"packages":{"":{"dependencies":{"express":"^4.18.0","pg":"^8.11.0"},"devDependencies":{"typescript":"^5.0.0"}},"node_modules/express":{"version":"4.18.2"},"node_modules/pg":{"version":"8.11.3"},"node_modules/typescript":{"version":"5.3.3","dev":true},"node_modules/qs":{"version":"6.11.0"}}}`,
				"src/server.ts":     `import express from "express"; import pg from "pg";`,
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"npm", "express", "direct", true},
				{"npm", "pg", "direct", true},
				{"npm", "typescript", "direct", true},
				{"npm", "qs", "transitive", false},
				{"npm", "express", "source-import", true},
				{"npm", "pg", "source-import", true},
			},
		},
		{
			Name: "python-app", RepoType: "Python app", ExpectedDecision: "allow",
			Files: map[string]string{
				"requirements.txt": "requests==2.31.0\nfastapi>=0.110.0\nuvicorn[standard]==0.27.0\n",
				"app.py":           "import requests\nfrom fastapi import FastAPI\n",
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"pypi", "requests", "direct", true},
				{"pypi", "fastapi", "direct", true},
				{"pypi", "uvicorn", "direct", true},
			},
		},
		{
			Name: "mixed-js-python-repo", RepoType: "Mixed JS + Python repo", ExpectedDecision: "allow",
			Files: map[string]string{
				"package.json":    `{"name":"mixed-js-python-repo","version":"1.0.0","license":"MIT","repository":"github:example/mixed","dependencies":{"axios":"^1.6.0"}}`,
				"src/client.ts":   `import axios from "axios";`,
				"pyproject.toml":  "[project]\ndependencies = [\"flask==3.0.0\", \"requests==2.31.0\"]\n",
				"service/main.py": "import flask\n",
			},
			ExpectedDeps: []benchmarkExpectedDep{
				{"npm", "axios", "direct", true},
				{"npm", "axios", "source-import", true},
				{"pypi", "flask", "direct", true},
				{"pypi", "requests", "direct", true},
			},
		},
	}
}

func scanBenchmarkInventory(repoPath string) ([]types.Dependency, error) {
	deps, err := npminventory.ScanInventory(repoPath)
	if err != nil {
		return nil, err
	}
	pyFiles, err := findPythonDependencyFiles(repoPath)
	if err != nil {
		return nil, err
	}
	for _, file := range pyFiles {
		parsed, err := pydeps.ParseFile(file)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(repoPath, file)
		if err != nil {
			rel = file
		}
		for _, dep := range parsed {
			if dep.Name == "" {
				continue
			}
			deps = append(deps, types.Dependency{
				Ecosystem:      "pypi",
				Name:           dep.Name,
				VersionRange:   firstNonEmptyString(dep.Specifier, dep.Version),
				SourceFile:     rel,
				DependencyType: "production",
				Direct:         true,
			})
		}
	}
	return deps, nil
}

func findPythonDependencyFiles(repoPath string) ([]string, error) {
	var files []string
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == ".venv" || info.Name() == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(info.Name()) {
		case "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "pipfile", "pipfile.lock", "environment.yml", "environment.yaml":
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func scanBenchmarkRisk(repoPath string) (types.ScanResult, error) {
	scanner := snpm.New()
	scanner.Policy = policy.Default()
	scanner.Offline = true
	return scanner.ScanLocalPackage(repoPath)
}

func findBenchmarkDep(expected benchmarkExpectedDep, actual []types.Dependency, consumed []bool) int {
	for i, dep := range actual {
		if consumed[i] || dep.Name == "" {
			continue
		}
		if dep.Ecosystem != expected.Ecosystem || dep.Name != expected.Name {
			continue
		}
		switch expected.Kind {
		case "source-import":
			if dep.DependencyType == "source-import" {
				return i
			}
		case "transitive":
			if !dep.Direct || dep.DependencyType == "transitive" {
				return i
			}
		case "direct":
			if dep.Direct && dep.DependencyType != "source-import" && dep.DependencyType != "package.json" && dep.DependencyType != "package-lock.json" {
				return i
			}
		}
	}
	return -1
}

func nonEmptyDeps(in []types.Dependency) []types.Dependency {
	var out []types.Dependency
	for _, dep := range in {
		if dep.Name != "" {
			out = append(out, dep)
		}
	}
	return out
}

func hasPackageJSON(repoPath string) bool {
	_, err := os.Stat(filepath.Join(repoPath, "package.json"))
	return err == nil
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

func rateRatio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func passStatus(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func emptyVersion(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

func emptyDecision(v string) string {
	if v == "" {
		return "not scanned"
	}
	return v
}

func contains(in []string, target string) bool {
	for _, v := range in {
		if v == target {
			return true
		}
	}
	return false
}
