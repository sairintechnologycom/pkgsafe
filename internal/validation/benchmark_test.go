package validation

import (
	"bytes"
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
	if report.Metrics.NetworkFailures != 0 {
		t.Fatalf("expected no network failures in offline mode, got %d", report.Metrics.NetworkFailures)
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
