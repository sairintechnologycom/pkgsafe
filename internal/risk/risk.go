package risk

import (
	"time"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

func Evaluate(pkg types.PackageIdentity, reasons []types.Reason, lifecycle []string, suspicious []string, alternatives []string) types.ScanResult {
	score := 0
	block := false
	for _, r := range reasons {
		score += r.ScoreImpact
		if r.Severity == "critical" {
			block = true
		}
	}
	if score > 100 {
		score = 100
	}

	decision := types.DecisionAllow
	switch {
	case block || score >= 80:
		decision = types.DecisionBlock
	case score >= 30:
		decision = types.DecisionWarn
	default:
		decision = types.DecisionAllow
	}

	return types.ScanResult{
		Package:        pkg,
		Score:          score,
		Decision:       decision,
		Reasons:        reasons,
		Lifecycle:      lifecycle,
		Suspicious:     suspicious,
		SafeAlternates: alternatives,
		ScannedAt:      time.Now().UTC(),
	}
}
