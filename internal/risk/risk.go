package risk

import (
	"fmt"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func Evaluate(pkg types.PackageIdentity, findings []types.Reason, lifecycle []string, suspicious []string, alternatives []string, pol policy.Policy) types.ScanResult {
	score := 0
	forcedBlock := false
	var reasons []types.Reason

	for _, finding := range findings {
		rule, ok := policy.RuleFor(pol, finding.ID)
		if !ok {
			continue
		}
		reason := types.Reason{
			ID:          finding.ID,
			Severity:    rule.Severity,
			Description: finding.Description,
			Evidence:    finding.Evidence,
			ScoreImpact: rule.Score,
		}
		if reason.Description == "" {
			reason.Description = defaultMessage(reason.ID)
		}
		reasons = append(reasons, reason)
		score += reason.ScoreImpact
		if reason.ID == "credential_path_reference" || reason.ID == "blocked_package" || reason.ID == "known_malware_indicator" || reason.ID == "known_vulnerability_critical" || reason.Severity == "critical" {
			forcedBlock = true
		}
	}

	if policy.IsBlocked(pol, pkg.Ecosystem, pkg.Name) {
		if rule, ok := policy.RuleFor(pol, "blocked_package"); ok {
			reasons = append(reasons, types.Reason{
				ID:          "blocked_package",
				Severity:    rule.Severity,
				Description: "Package is listed as blocked by policy",
				ScoreImpact: rule.Score,
			})
			score += rule.Score
		}
		forcedBlock = true
	}

	if policy.IsTrusted(pol, pkg.Ecosystem, pkg.Name) && !forcedBlock {
		if rule, ok := policy.RuleFor(pol, "trusted_package_reduction"); ok {
			reasons = append(reasons, types.Reason{
				ID:          "trusted_package_reduction",
				Severity:    rule.Severity,
				Description: "Package is listed as trusted by policy",
				ScoreImpact: rule.Score,
			})
			score += rule.Score
		}
	}

	score = clamp(score, 0, 100)
	decision := Decide(score, forcedBlock, pol.Thresholds)

	return types.ScanResult{
		Package:        pkg,
		Mode:           string(pol.Mode),
		Score:          score,
		Decision:       decision,
		Thresholds:     pol.Thresholds,
		Reasons:        dedupeReasons(reasons),
		Lifecycle:      lifecycle,
		Suspicious:     suspicious,
		SafeAlternates: alternatives,
		Enforcement:    Enforcement(decision, pol.Mode),
		Recommended:    RecommendedAction(decision, pol.Mode),
		ScannedAt:      time.Now().UTC(),
	}
}

func Decide(score int, forcedBlock bool, t types.Thresholds) types.Decision {
	if forcedBlock {
		return types.DecisionBlock
	}
	switch {
	case score >= t.BlockMinScore:
		return types.DecisionBlock
	case score > t.AllowMaxScore && score <= t.WarnMaxScore:
		return types.DecisionWarn
	default:
		return types.DecisionAllow
	}
}

func Enforcement(decision types.Decision, mode policy.Mode) string {
	switch mode {
	case policy.ModeAudit:
		return "Not blocked"
	case policy.ModeBlock:
		if decision == types.DecisionBlock {
			return "Install should not proceed"
		}
		return "Install may proceed"
	default:
		if decision == types.DecisionBlock {
			return "Install should not proceed"
		}
		if decision == types.DecisionWarn {
			return "User review recommended"
		}
		return "Install may proceed"
	}
}

func RecommendedAction(decision types.Decision, mode policy.Mode) string {
	if mode == policy.ModeAudit {
		switch decision {
		case types.DecisionBlock:
			return "Audit only. Package would be blocked outside audit mode."
		case types.DecisionWarn:
			return "Audit only. Review package before installing."
		default:
			return "Audit only. Package appears safe based on current checks."
		}
	}
	switch decision {
	case types.DecisionBlock:
		return "Do not install this package."
	case types.DecisionWarn:
		return "Review package before installing."
	default:
		return "Package appears safe to install based on current checks."
	}
}

func AddReason(findings []types.Reason, id, message, evidence string) []types.Reason {
	return append(findings, types.Reason{ID: id, Description: message, Evidence: evidence})
}

func NewPackageFinding(ageDays int) types.Reason {
	return types.Reason{
		ID:          "new_package",
		Description: fmt.Sprintf("Package version was published recently (%d days ago)", ageDays),
	}
}

func defaultMessage(id string) string {
	switch id {
	case "lifecycle_script_present":
		return "Package defines an install lifecycle script"
	case "network_command_in_lifecycle":
		return "Lifecycle script uses a network command"
	case "credential_path_reference":
		return "Lifecycle script references a protected credential path"
	case "secret_keyword_reference":
		return "Lifecycle script references secret-related keywords"
	case "obfuscated_script":
		return "Lifecycle script contains obfuscation indicators"
	case "typosquat_candidate":
		return "Package name resembles a popular package"
	case "missing_repository":
		return "Package metadata does not include a source repository"
	case "missing_license":
		return "Package metadata does not include a license"
	case "new_package":
		return "Package version was published recently"
	case "known_vulnerability_critical":
		return "Package version has a critical severity advisory"
	case "known_vulnerability_high":
		return "Package version has a high severity advisory"
	case "known_vulnerability_medium":
		return "Package version has a medium severity advisory"
	case "known_vulnerability_low":
		return "Package version has a low severity advisory"
	case "known_malware_indicator":
		return "Package contains malware or malicious code"
	default:
		return id
	}
}

func clamp(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func dedupeReasons(in []types.Reason) []types.Reason {
	seen := map[string]bool{}
	out := []types.Reason{}
	for _, r := range in {
		key := r.ID + ":" + r.Evidence + ":" + r.Description
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}
