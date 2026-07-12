package validation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBenchmarkPack(t *testing.T) {
	dir := t.TempDir()
	report, err := RunBenchmarkPack(dir)
	if err != nil {
		t.Fatalf("RunBenchmarkPack() error = %v", err)
	}
	if !report.Pass {
		t.Fatalf("expected benchmark pack to pass, got report: %+v", report)
	}
	if got := len(report.Results); got != 7 {
		t.Fatalf("expected 7 benchmark fixtures, got %d", got)
	}
	if report.Metrics.DirectDependencyRecall < 0.95 {
		t.Fatalf("direct recall too low: %.2f", report.Metrics.DirectDependencyRecall)
	}
	if report.Metrics.TransitiveDependencyRecall < 0.90 {
		t.Fatalf("transitive recall too low: %.2f", report.Metrics.TransitiveDependencyRecall)
	}
	if report.Metrics.SourceImportRecall < 0.85 {
		t.Fatalf("source import recall too low: %.2f", report.Metrics.SourceImportRecall)
	}
	if report.Metrics.KnownGoodFalseBlockRate != 0 {
		t.Fatalf("expected zero false block rate, got %.2f", report.Metrics.KnownGoodFalseBlockRate)
	}
}

func TestLoadBenchmarkDefinitions(t *testing.T) {
	dir := t.TempDir()
	if err := WriteDefaultBenchmarkDefinitions(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadBenchmarkDefinitions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected benchmark package entries")
	}
	if entries[0].Ecosystem == "" || entries[0].Name == "" || entries[0].ExpectedDecision == "" {
		t.Fatalf("definition not normalized: %+v", entries[0])
	}
}

func TestBenchmarkOfflineCacheMissesAreReported(t *testing.T) {
	dir := t.TempDir()
	defs := t.TempDir()
	if err := WriteDefaultBenchmarkDefinitions(defs); err != nil {
		t.Fatal(err)
	}
	report, err := RunBenchmarkPackWithOptions(BenchmarkOptions{
		FixturesDir:    dir,
		DefinitionsDir: defs,
		Offline:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Pass {
		t.Fatalf("offline cache misses should be reported without failing deterministic fixture checks: %+v", report.Metrics)
	}
	if report.Metrics.OfflineCacheMisses == 0 {
		t.Fatal("expected offline cache misses")
	}
	if report.Metrics.PackagesSkipped != report.Metrics.OfflineCacheMisses {
		t.Fatalf("skipped=%d cache_misses=%d", report.Metrics.PackagesSkipped, report.Metrics.OfflineCacheMisses)
	}
	if report.Metrics.PackagesPassed > report.Metrics.PackagesExecuted {
		t.Fatalf("skips counted as passes: %+v", report.Metrics)
	}
	if report.Metrics.CandidateStatusEligible {
		t.Fatalf("cache-miss-heavy benchmark must not be candidate eligible: %+v", report.Metrics)
	}
	for _, result := range report.Packages {
		if result.Skipped && result.Passed {
			t.Fatalf("skipped result marked passed: %+v", result)
		}
	}
	if report.Metrics.NetworkFailures != 0 {
		t.Fatalf("expected no network failures in offline mode, got %d", report.Metrics.NetworkFailures)
	}
}

func TestPackageEvidenceEligibilityMatrix(t *testing.T) {
	cases := []struct {
		name       string
		configured int
		executed   int
		failed     int
		eligible   bool
	}{
		{name: "zero executed", configured: 25, executed: 0, eligible: false},
		{name: "one executed", configured: 25, executed: 1, eligible: false},
		{name: "partial below coverage", configured: 25, executed: 19, eligible: false},
		{name: "threshold met", configured: 25, executed: 20, eligible: true},
		{name: "executed failure", configured: 25, executed: 25, failed: 1, eligible: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := make([]BenchmarkPackageResult, tc.configured)
			for i := range results {
				results[i] = BenchmarkPackageResult{Name: "pkg", Skipped: true, SkipReason: "offline cache miss"}
			}
			for i := 0; i < tc.executed; i++ {
				results[i] = BenchmarkPackageResult{Name: "pkg", Attempted: true, Executed: true, Passed: i >= tc.failed}
			}
			var report BenchmarkReport
			applyPackageMetrics(&report, results)
			if report.Metrics.CandidateStatusEligible != tc.eligible {
				t.Fatalf("eligible=%t want %t metrics=%+v", report.Metrics.CandidateStatusEligible, tc.eligible, report.Metrics)
			}
			if report.Metrics.PackagesConfigured != tc.configured || report.Metrics.PackagesExecuted != tc.executed || report.Metrics.PackagesSkipped != tc.configured-tc.executed {
				t.Fatalf("incorrect disjoint accounting: %+v", report.Metrics)
			}
		})
	}
}

func TestOnlineSummaryClassifiesPartialAvailability(t *testing.T) {
	results := []BenchmarkPackageResult{
		{Name: "pass", Attempted: true, Executed: true, Passed: true},
		{Name: "mismatch", Attempted: true, Executed: true, Passed: false, FailureCategory: "expectation_mismatch"},
		{Name: "network", Attempted: true, Skipped: true, SkipReason: "network_unavailable"},
		{Name: "missing", Attempted: true, Skipped: true, SkipReason: "package_not_found"},
		{Name: "scanner", Attempted: true, Skipped: true, SkipReason: "scanner_failure"},
	}
	var report BenchmarkReport
	applyOnlineSummary(&report, results, false)
	got := report.Online
	if got.Configured != 5 || got.Attempted != 5 || got.Executed != 2 || got.Passed != 1 || got.Failed != 1 || got.Skipped != 3 {
		t.Fatalf("incorrect online accounting: %+v", got)
	}
	if got.Status != "fail" || got.ExpectationMismatches != 1 || got.NetworkUnavailable != 1 || got.PackageNotFound != 1 || got.ScannerFailures != 1 {
		t.Fatalf("incorrect failure classification: %+v", got)
	}
}

func TestOnlineSummaryDistinguishesNoExecutedSamples(t *testing.T) {
	results := []BenchmarkPackageResult{
		{Name: "network", Attempted: true, Skipped: true, SkipReason: "network_unavailable"},
		{Name: "missing", Attempted: true, Skipped: true, SkipReason: "package_not_found"},
	}
	var report BenchmarkReport
	applyOnlineSummary(&report, results, false)
	if report.Online.Status != "no_executed_samples" {
		t.Fatalf("expected no_executed_samples, got %+v", report.Online)
	}
	if report.Online.Executed != 0 || report.Online.Skipped != 2 || report.Online.Attempted != 2 {
		t.Fatalf("incorrect accounting for no-execution case: %+v", report.Online)
	}
}

func TestWriteBenchmarkReportHuman(t *testing.T) {
	report, err := RunBenchmarkPack(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteBenchmarkReport(&buf, report, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"PkgSafe Real-World Benchmark Pack",
		"Direct dependency recall:",
		"mixed-js-python-repo",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("human report missing %q:\n%s", want, out)
		}
	}
}

func TestRunBenchmarkWithRepoListMultiEcosystem(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "mixed")
	if err := os.MkdirAll(filepath.Join(repo, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"package.json":     `{"name":"mixed","version":"1.0.0","license":"MIT","repository":"github:example/mixed","dependencies":{"axios":"^1.6.0"}}`,
		"src/client.ts":    `import axios from "axios";`,
		"requirements.txt": "requests==2.31.0\n",
		"go.mod":           "module example.com/mixed\n\nrequire github.com/google/uuid v1.6.0\n",
		"Cargo.lock":       "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n",
	}
	for rel, content := range files {
		path := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	repoList := filepath.Join(root, "repos.json")
	body := `[{"name":"mixed","path":"` + repo + `","ecosystems":["npm","pypi","go","cargo"],"repo_type":"mixed-js-python-repo","expected_min_direct_dependencies":3,"expected_no_false_block":true,"behavior_mode":"disabled","offline":true}]`
	if err := os.WriteFile(repoList, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := RunBenchmarkPackWithOptions(BenchmarkOptions{
		FixturesDir:    filepath.Join(root, "fixtures"),
		DefinitionsDir: filepath.Join(root, "defs"),
		RepoListPath:   repoList,
		Offline:        true,
		Update:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.RealRepoValidationCount != 1 {
		t.Fatalf("real repo count = %d, want 1", report.Metrics.RealRepoValidationCount)
	}
	if report.Metrics.NPMRepoCount != 1 || report.Metrics.PyPIRepoCount != 1 || report.Metrics.GoRepoCount != 1 || report.Metrics.CargoRepoCount != 1 {
		t.Fatalf("ecosystem counts not recorded: %+v", report.Metrics)
	}
	if report.Metrics.FalseBlockCount != 0 || report.Metrics.ScannerCrashCount != 0 {
		t.Fatalf("unexpected failures: %+v", report.Metrics)
	}
	if len(report.RepoValidations) != 1 || report.RepoValidations[0].ScanDurationMs <= 0 {
		t.Fatalf("repo validation duration not recorded: %+v", report.RepoValidations)
	}
	if report.RepoValidations[0].InventoryDurationMs <= 0 ||
		report.RepoValidations[0].CIScanDurationMs <= 0 ||
		report.RepoValidations[0].OutputGenerationDurationMs <= 0 {
		t.Fatalf("repo validation phase durations not recorded: %+v", report.RepoValidations[0])
	}
	if report.RepoValidations[0].EvidencePackGenerated && report.RepoValidations[0].EvidencePackDurationMs <= 0 {
		t.Fatalf("repo validation evidence duration not recorded: %+v", report.RepoValidations[0])
	}
	if report.Metrics.RealRepoAverageScanDurationMs <= 0 || report.Metrics.RealRepoP95ScanDurationMs <= 0 {
		t.Fatalf("real repo duration metrics not recorded: %+v", report.Metrics)
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"real_repo_validation_count", "behavior_mode_used", "repo_validations"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("benchmark JSON missing %q: %s", want, string(b))
		}
	}
}

func TestRunBenchmarkRepoListMissingPathFails(t *testing.T) {
	root := t.TempDir()
	repoList := filepath.Join(root, "repos.json")
	body := `[{"name":"missing","path":"does-not-exist","ecosystems":["npm"],"repo_type":"npm-simple-app","expected_no_false_block":true,"behavior_mode":"disabled"}]`
	if err := os.WriteFile(repoList, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := RunBenchmarkPackWithOptions(BenchmarkOptions{
		FixturesDir:    filepath.Join(root, "fixtures"),
		DefinitionsDir: filepath.Join(root, "defs"),
		RepoListPath:   repoList,
		Offline:        true,
		Update:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Pass {
		t.Fatal("missing repo path should fail benchmark")
	}
	if report.Metrics.ScannerCrashCount == 0 {
		t.Fatalf("expected scanner crash/missing path count, got %+v", report.Metrics)
	}
}

func TestClassifyPackageScanError(t *testing.T) {
	cases := map[string]string{
		`Get "https://registry.npmjs.org/axios": dial tcp: lookup registry.npmjs.org: no such host`: "network_unavailable",
		`registry returned 503 service unavailable`:                                                 "registry_unavailable",
		`package not found`:                         "package_not_found",
		`parse package metadata: invalid character`: "scanner_failure",
	}
	for msg, want := range cases {
		if got := classifyPackageScanError(errTestType(msg)); got != want {
			t.Fatalf("classifyPackageScanError(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestValidateRealRepoSpecBatchOneAliasesAndFalseWarnRate(t *testing.T) {
	for _, repoType := range []string{"small-npm-app", "react-vite-next-app", "npm-workspace-monorepo", "internal-private-package-repo"} {
		spec := RealRepoSpec{
			Name:                     "repo",
			Path:                     "/tmp/repo",
			RepoType:                 repoType,
			ExpectedMaxFalseWarnRate: 0.10,
		}
		if err := validateRealRepoSpec(spec); err != nil {
			t.Fatalf("validateRealRepoSpec(%q) error = %v", repoType, err)
		}
	}

	spec := RealRepoSpec{
		Name:                     "repo",
		Path:                     "/tmp/repo",
		RepoType:                 "small-npm-app",
		ExpectedMaxFalseWarnRate: 10,
	}
	if err := validateRealRepoSpec(spec); err == nil {
		t.Fatal("expected percentage-style false warn threshold to fail")
	}
}

func TestRunBenchmarkRepoListEmptyRepoHandled(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "empty")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	repoList := filepath.Join(root, "repos.json")
	body := `[{"name":"empty","path":"` + repo + `","ecosystems":["npm"],"repo_type":"npm-simple-app","expected_min_direct_dependencies":0,"expected_no_false_block":true,"behavior_mode":"disabled","offline":true}]`
	if err := os.WriteFile(repoList, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := RunBenchmarkPackWithOptions(BenchmarkOptions{
		FixturesDir:    filepath.Join(root, "fixtures"),
		DefinitionsDir: filepath.Join(root, "defs"),
		RepoListPath:   repoList,
		Offline:        true,
		Update:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.RealRepoValidationCount != 1 {
		t.Fatalf("real repo count = %d, want 1", report.Metrics.RealRepoValidationCount)
	}
	if report.Metrics.ScannerCrashCount != 0 {
		t.Fatalf("empty repo should not be a scanner crash: %+v", report.Metrics)
	}
}
