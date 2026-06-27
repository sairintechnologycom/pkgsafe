package validation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAlphaReadinessGate(t *testing.T) {
	// Locate or write fixtures
	corpusDir := filepath.Join("..", "..", "testdata", "corpus")
	goldenFile := filepath.Join("..", "..", "testdata", "corpus-golden.json")

	// Ensure the folders exist
	_ = os.MkdirAll(filepath.Dir(goldenFile), 0755)

	report, err := RunAlphaReadiness(corpusDir, goldenFile)
	if err != nil {
		t.Fatalf("failed to run alpha readiness validation: %v", err)
	}

	if !report.Pass {
		t.Errorf("Alpha readiness gate failed! Report: %+v", report)
	}

	if report.FinalReadiness != "INTERNAL_ALPHA_READY" {
		t.Errorf("Expected readiness status to be INTERNAL_ALPHA_READY, got %q", report.FinalReadiness)
	}
}
