package cli

import (
	"fmt"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// resolveScanFailOn picks the fail-on threshold for scan commands.
// Explicit values win. In block mode the default is "block" so scripts like
// `pkgsafe scan-npm-package foo --mode block && npm install foo` fail closed.
// In warn/audit modes the default is "none" so interactive review stays usable.
func resolveScanFailOn(mode policy.Mode, failOn string) string {
	failOn = strings.ToLower(strings.TrimSpace(failOn))
	switch failOn {
	case "none", "warn", "block":
		return failOn
	case "":
		if mode == policy.ModeBlock {
			return "block"
		}
		return "none"
	default:
		return ""
	}
}

// validateScanFailOn returns an error when fail-on is set to an unknown value.
func validateScanFailOn(failOn string) error {
	if strings.TrimSpace(failOn) == "" {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "none", "warn", "block":
		return nil
	default:
		return fmt.Errorf("invalid --fail-on value %q (want none, warn, or block)", failOn)
	}
}

// worstDecision returns the most severe decision among the provided results.
func worstDecision(results []types.ScanResult) types.Decision {
	worst := types.DecisionAllow
	for _, res := range results {
		worst = worseDecision(worst, res.Decision)
	}
	return worst
}

func worseDecision(current, candidate types.Decision) types.Decision {
	rank := func(d types.Decision) int {
		switch d {
		case types.DecisionBlock:
			return 4
		case types.DecisionReviewRequired:
			return 3
		case types.DecisionWarn:
			return 2
		case types.DecisionAllow:
			return 1
		default:
			return 0
		}
	}
	if rank(candidate) > rank(current) {
		return candidate
	}
	return current
}

// exitIfScanFails returns a non-zero exitError when decision meets the fail-on
// threshold. review_required is treated as blocking under fail-on=block, matching
// install-guard semantics.
func exitIfScanFails(decision types.Decision, mode policy.Mode, failOn string) error {
	if err := validateScanFailOn(failOn); err != nil {
		return exitError{code: 2, err: err}
	}
	threshold := resolveScanFailOn(mode, failOn)
	switch threshold {
	case "none":
		return nil
	case "block":
		if decision == types.DecisionBlock || decision == types.DecisionReviewRequired {
			return exitError{
				code: 1,
				err:  fmt.Errorf("scan failed: decision=%s (fail-on=%s)", decision, threshold),
			}
		}
	case "warn":
		if decision == types.DecisionBlock || decision == types.DecisionReviewRequired || decision == types.DecisionWarn {
			return exitError{
				code: 1,
				err:  fmt.Errorf("scan failed: decision=%s (fail-on=%s)", decision, threshold),
			}
		}
	}
	return nil
}

// exitIfScanResultsFail is exitIfScanFails over an aggregate of package results.
func exitIfScanResultsFail(results []types.ScanResult, mode policy.Mode, failOn string) error {
	if len(results) == 0 {
		return nil
	}
	return exitIfScanFails(worstDecision(results), mode, failOn)
}
