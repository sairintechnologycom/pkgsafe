package risk

import (
	"fmt"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func ApplyEnterpriseControls(
	res types.ScanResult,
	pol policy.Policy,
	regName string,
	regCfg policy.RegistryConfig,
	requestedBy string,
	env string,
) types.ScanResult {
	// Initialize default evidence objects
	res.PolicyInfo = &types.PolicyEvidence{
		Source:  "local",
		Name:    "default",
		Version: "0.1.0",
		Owner:   "local",
	}
	if pol.PolicyPackName != "" {
		res.PolicyInfo = &types.PolicyEvidence{
			Source:  pol.PolicyPackSource,
			Name:    pol.PolicyPackName,
			Version: pol.PolicyPackVersion,
			Owner:   pol.PolicyPackOwner,
		}
	}

	res.RegistryInfo = &types.RegistryEvidence{
		Name:       regName,
		Type:       regCfg.Type,
		URL:        registry.RedactURL(regCfg.URL),
		AuthMethod: regCfg.Auth.Method,
	}

	res.TrustInfo = &types.TrustEvidence{Matched: false}
	res.ExceptionInfo = &types.ExceptionEvidence{Matched: false}

	// 1. Run private registry rules
	regFindings := CheckPrivateRegistryRules(res.Package, regName, regCfg, pol)
	for _, f := range regFindings {
		res.Reasons = append(res.Reasons, f)
		res.Score += f.ScoreImpact
	}

	// Check if unapproved registry URL
	// E.g., if it is not default, and not one of configured registries
	if regName == "" {
		res.Reasons = append(res.Reasons, types.Reason{
			ID:          "unapproved_registry_url",
			Severity:    "critical",
			Description: "Package resolved from unapproved registry URL",
			ScoreImpact: 100,
		})
		res.Score += 100
	}

	// 2. Check Blocked Package Rules (Overrides Trust)
	blockRule, blockedMatched := policy.FindBlockedPackageRule(pol, res.Package.Ecosystem, res.Package.Name, res.Package.Version, regName)
	if blockedMatched {
		res.Reasons = append(res.Reasons, types.Reason{
			ID:          "blocked_package",
			Severity:    blockRule.Severity,
			Description: fmt.Sprintf("Blocked by policy pack blocked list: %s", blockRule.Reason),
			ScoreImpact: 100,
		})
		res.Score = 100
	}

	// 3. Match and Apply Scoped Rules
	var matchedScopedRules []policy.ScopedRule
	for _, rule := range pol.ScopedRules {
		if policy.MatchScopedRule(rule, res.Package, regName, requestedBy) {
			matchedScopedRules = append(matchedScopedRules, rule)
			// Apply TrustScoreDelta
			res.Score += rule.Apply.TrustScoreDelta

			// Apply BlockOnUnknownRegistry
			if rule.Apply.BlockOnUnknownRegistry && (regName == "default" || regName == "" || regCfg.Type == "unknown") {
				res.Score = 100
				res.Reasons = append(res.Reasons, types.Reason{
					ID:          "unknown_registry_block",
					Severity:    "critical",
					Description: "AI agent strict mode: Block on unknown registry",
					ScoreImpact: 100,
				})
			}
		}
	}

	// Check known malware or critical credential issues
	hasMalware := false
	for _, r := range res.Reasons {
		if r.ID == "known_malware_indicator" || r.ID == "credential_path_reference" {
			hasMalware = true
			break
		}
	}

	// 4. Check Trusted Package Rules
	trustRule, trustMatched := policy.FindTrustedPackageRule(pol, res.Package.Ecosystem, res.Package.Name, res.Package.Version, regName)
	if trustMatched && !blockedMatched && !hasMalware {
		res.TrustInfo = &types.TrustEvidence{
			Matched: true,
			RuleID:  "trusted_internal_scope",
			Reason:  trustRule.Reason,
		}
		// Trusted reduction
		res.Score -= 20
		res.Reasons = append(res.Reasons, types.Reason{
			ID:          "trusted_package_reduction",
			Severity:    "informational",
			Description: fmt.Sprintf("Package matches trusted package rule: %s", trustRule.Reason),
			ScoreImpact: -20,
		})
	}

	res.Score = clamp(res.Score, 0, 100)

	// Determine decision before exceptions
	blockThreshold := pol.Thresholds.BlockMinScore
	warnThreshold := pol.Thresholds.WarnMaxScore
	allowThreshold := pol.Thresholds.AllowMaxScore

	// Apply custom scoped rule thresholds if matched
	for _, rule := range matchedScopedRules {
		if rule.Apply.BlockMinScore > 0 {
			blockThreshold = rule.Apply.BlockMinScore
		}
		if rule.Apply.WarnMinScore > 0 {
			warnThreshold = rule.Apply.WarnMinScore
		}
	}

	forcedBlock := blockedMatched || hasMalware || res.Score >= blockThreshold

	if forcedBlock {
		res.Decision = types.DecisionBlock
	} else if res.Score > allowThreshold && res.Score <= warnThreshold {
		res.Decision = types.DecisionWarn
	} else {
		res.Decision = types.DecisionAllow
	}

	// 5. Apply Exception rules (reduces BLOCK to WARN if allowed)
	exc, excMatched := policy.FindActiveException(pol, res.Package, env)
	if excMatched && res.Decision == types.DecisionBlock {
		// Exceptions cannot override known malware unless policy explicitly permits
		if !hasMalware {
			res.ExceptionInfo = &types.ExceptionEvidence{
				Matched:    true,
				RuleID:     exc.ID,
				Reason:     exc.Reason,
				ValidUntil: exc.AllowedUntil.Format("2006-01-02"),
			}
			res.Decision = types.DecisionWarn
			res.Reasons = append(res.Reasons, types.Reason{
				ID:          "active_exception",
				Severity:    "informational",
				Description: fmt.Sprintf("Exception active: %s (Approved by %s)", exc.Reason, exc.ApprovedBy),
				ScoreImpact: 0,
			})
		}
	}

	// Apply Scoped Rule WarnInstallAllowed
	for _, rule := range matchedScopedRules {
		if !rule.Apply.WarnInstallAllowed && res.Decision == types.DecisionWarn {
			res.Decision = types.DecisionBlock
			res.Reasons = append(res.Reasons, types.Reason{
				ID:          "scoped_warn_block",
				Severity:    "critical",
				Description: "AI agent strict mode: Warnings are treated as blocks",
				ScoreImpact: 100,
			})
		}
	}

	// Dedupe reasons
	res.Reasons = dedupeReasons(res.Reasons)

	// Update Action & Enforcement
	res.Enforcement = Enforcement(res.Decision, pol.Mode)
	res.Recommended = RecommendedAction(res.Decision, pol.Mode)

	return res
}
