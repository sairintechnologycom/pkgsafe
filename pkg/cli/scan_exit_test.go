package cli

import (
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestResolveScanFailOn(t *testing.T) {
	cases := []struct {
		mode   policy.Mode
		failOn string
		want   string
	}{
		{policy.ModeBlock, "", "block"},
		{policy.ModeWarn, "", "none"},
		{policy.ModeAudit, "", "none"},
		{policy.ModeWarn, "block", "block"},
		{policy.ModeBlock, "none", "none"},
		{policy.ModeBlock, "warn", "warn"},
	}
	for _, tc := range cases {
		got := resolveScanFailOn(tc.mode, tc.failOn)
		if got != tc.want {
			t.Fatalf("resolveScanFailOn(%q, %q)=%q want %q", tc.mode, tc.failOn, got, tc.want)
		}
	}
}

func TestExitIfScanFailsBlockMode(t *testing.T) {
	err := exitIfScanFails(types.DecisionBlock, policy.ModeBlock, "")
	eErr, ok := err.(exitError)
	if !ok {
		t.Fatalf("expected exitError, got %T (%v)", err, err)
	}
	if eErr.code != 1 {
		t.Fatalf("expected exit code 1, got %d", eErr.code)
	}

	if err := exitIfScanFails(types.DecisionAllow, policy.ModeBlock, ""); err != nil {
		t.Fatalf("allow should not fail in block mode: %v", err)
	}
	if err := exitIfScanFails(types.DecisionBlock, policy.ModeWarn, ""); err != nil {
		t.Fatalf("warn mode default should not fail: %v", err)
	}
	if err := exitIfScanFails(types.DecisionBlock, policy.ModeWarn, "block"); err == nil {
		t.Fatal("explicit fail-on=block should fail on block in warn mode")
	}
	if err := exitIfScanFails(types.DecisionReviewRequired, policy.ModeBlock, ""); err == nil {
		t.Fatal("review_required should fail under fail-on=block")
	}
	if err := exitIfScanFails(types.DecisionWarn, policy.ModeBlock, "warn"); err == nil {
		t.Fatal("fail-on=warn should fail on warn")
	}
}

func TestWorstDecision(t *testing.T) {
	results := []types.ScanResult{
		{Decision: types.DecisionAllow},
		{Decision: types.DecisionWarn},
		{Decision: types.DecisionReviewRequired},
	}
	if got := worstDecision(results); got != types.DecisionReviewRequired {
		t.Fatalf("got %s want review_required", got)
	}
	results = append(results, types.ScanResult{Decision: types.DecisionBlock})
	if got := worstDecision(results); got != types.DecisionBlock {
		t.Fatalf("got %s want block", got)
	}
}
