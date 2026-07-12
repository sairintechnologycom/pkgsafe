package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// BuildPackageProfile assembles the canonical package assessment object used by
// CLI, MCP, JSON, evidence, and audit-style outputs.
func BuildPackageProfile(res types.ScanResult, pol policy.Policy) types.PackageProfile {
	reasons := make([]string, 0, len(res.Reasons))
	hardBlocks := make([]string, 0)
	identityReasons := make([]string, 0)
	registryReasons := make([]string, 0)
	for _, r := range res.Reasons {
		if r.Description != "" {
			reasons = append(reasons, r.Description)
		} else {
			reasons = append(reasons, r.ID)
		}
		if isHardBlockReason(pol, r) {
			hardBlocks = append(hardBlocks, r.ID)
		}
		if isIdentityRiskReason(r.ID) {
			identityReasons = append(identityReasons, r.ID)
		}
		if isRegistryRiskReason(r.ID) {
			registryReasons = append(registryReasons, r.ID)
		}
	}

	behavior := types.PackageBehaviorSignal{
		Mode:          res.Sandbox.BehaviorMode,
		Executed:      len(res.Sandbox.ScriptsExecuted) > 0,
		Isolated:      res.Sandbox.Isolated,
		Runner:        res.Sandbox.Runner,
		NetworkPolicy: res.Sandbox.NetworkMode,
		Warning:       res.Sandbox.Warning,
		NotPerformed:  res.Sandbox.NotPerformed,
		Reason:        res.Sandbox.NotPerfReason,
	}
	if behavior.Mode == "" {
		behavior.Mode = types.BehaviorDisabled
	}
	switch behavior.Mode {
	case types.BehaviorHeuristic:
		behavior.Limitations = []string{
			"non-isolated host runner",
			"not a security sandbox",
			"network policy is advisory unless an isolated backend is active",
		}
	case types.BehaviorIsolated:
		if !res.Sandbox.Available {
			behavior.Limitations = []string{"isolated backend unavailable"}
		}
	}

	registry := ""
	if res.RegistryInfo != nil {
		registry = firstNonEmpty(res.RegistryInfo.URL, res.RegistryInfo.Name)
	}
	policySource := "local"
	policyName := "default"
	policyVersion := "0.1.0"
	if res.PolicyInfo != nil {
		policySource = firstNonEmpty(res.PolicyInfo.Source, policySource)
		policyName = firstNonEmpty(res.PolicyInfo.Name, policyName)
		policyVersion = firstNonEmpty(res.PolicyInfo.Version, policyVersion)
	}

	return types.PackageProfile{
		SchemaVersion: "1.0",
		Package: types.PackageProfileIdentity{
			Ecosystem:        res.Package.Ecosystem,
			Name:             res.Package.Name,
			RequestedVersion: res.Package.Version,
			ResolvedVersion:  res.Package.Version,
			Registry:         registry,
		},
		Decision:        res.Decision,
		RiskScore:       res.Score,
		Confidence:      profileConfidence(res),
		HardBlocks:      uniqueStrings(hardBlocks),
		TopReasons:      firstStrings(reasons, 5),
		Vulnerabilities: res.Vulnerabilities,
		BehaviorSignals: []types.PackageBehaviorSignal{behavior},
		IdentityRisk: types.PackageRiskFacet{
			Score:   facetScore(res, identityReasons),
			Reasons: uniqueStrings(identityReasons),
		},
		RegistryRisk: types.PackageRiskFacet{
			Score:   facetScore(res, registryReasons),
			Reasons: uniqueStrings(registryReasons),
		},
		Provenance: types.PackageProvenance{
			ScannedAt:     res.ScannedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			PolicySource:  policySource,
			PolicyName:    policyName,
			PolicyVersion: policyVersion,
			Registry:      registry,
		},
		Policy: types.PackageProfilePolicy{
			Mode:              string(pol.Mode),
			Thresholds:        pol.Thresholds,
			Enforcement:       res.Enforcement,
			RecommendedAction: res.Recommended,
		},
		Remediation: append([]string{}, res.SafeAlternates...),
		EvidenceID:  profileEvidenceID(res),
	}
}

func isHardBlockReason(pol policy.Policy, r types.Reason) bool {
	if r.ScoreImpact >= 100 || strings.EqualFold(r.Severity, "critical") {
		return true
	}
	switch policy.EnforcementClassFor(pol, r.ID) {
	case policy.EnforcementSecurityBlock, policy.EnforcementPolicyBlock:
		return true
	default:
		return false
	}
}

func isIdentityRiskReason(id string) bool {
	switch {
	case strings.Contains(id, "typosquat"),
		strings.Contains(id, "ai_package_squatting"),
		id == "missing_repository",
		id == "missing_license",
		id == "new_package":
		return true
	default:
		return false
	}
}

func isRegistryRiskReason(id string) bool {
	switch {
	case strings.Contains(id, "registry"),
		strings.Contains(id, "confusion"),
		strings.Contains(id, "private_scope"),
		strings.Contains(id, "private_prefix"),
		id == "unapproved_registry_url",
		id == "unknown_registry_block":
		return true
	default:
		return false
	}
}

func profileConfidence(res types.ScanResult) string {
	switch {
	case res.Decision == types.DecisionBlock:
		return "high"
	case len(res.Vulnerabilities) > 0:
		return "medium"
	case res.Score >= 40:
		return "medium"
	default:
		return "high"
	}
}

func profileEvidenceID(res types.ScanResult) string {
	h := sha256.New()
	_, _ = h.Write([]byte(res.Package.Ecosystem))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(res.Package.Name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(res.Package.Version))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(res.Decision))
	_, _ = h.Write([]byte(fmt.Sprintf(":%d:%s", res.Score, res.ScannedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"))))
	return "profile-" + hex.EncodeToString(h.Sum(nil))[:20]
}

func facetScore(res types.ScanResult, ids []string) int {
	if len(ids) == 0 {
		return 0
	}
	score := 0
	for _, r := range res.Reasons {
		for _, id := range ids {
			if r.ID == id {
				score += r.ScoreImpact
			}
		}
	}
	if score < 0 {
		return 0
	}
	return score
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstStrings(in []string, limit int) []string {
	if len(in) <= limit {
		return uniqueStrings(in)
	}
	return uniqueStrings(in[:limit])
}
