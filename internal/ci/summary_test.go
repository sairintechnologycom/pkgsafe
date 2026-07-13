package ci

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteHumanSummaryChangedOnlyZeroPackages(t *testing.T) {
	var buf bytes.Buffer
	WriteHumanSummary(&buf, &ScanResult{
		Decision:    "allow",
		Mode:        "warn",
		FailOn:      "block",
		Lockfile:    "package-lock.json",
		Ecosystem:   "npm",
		ChangedOnly: true,
		Summary:     Summary{PackagesScanned: 0},
	})
	out := buf.String()
	if !strings.Contains(out, "changed-only scan found 0 packages") {
		t.Fatalf("expected zero-package notice, got:\n%s", out)
	}
	if !strings.Contains(out, "not that the full project is clean") {
		t.Fatalf("expected full-project disclaimer, got:\n%s", out)
	}
	if !strings.Contains(out, "No dependency changes to gate") {
		t.Fatalf("expected recommended action for zero changes, got:\n%s", out)
	}
}
