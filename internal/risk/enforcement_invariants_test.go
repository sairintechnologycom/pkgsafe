package risk

import (
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestSecurityBlocksCannotBeDowngraded(t *testing.T) {
	securityRules := []string{
		"known_malware_indicator",
		"credential_path_reference",
		"dependency_confusion_candidate",
		"private_scope_public_registry",
		"unapproved_registry_url",
	}
	for _, ruleID := range securityRules {
		t.Run(ruleID, func(t *testing.T) {
			pol := invariantPolicy("@company/package")
			base := Evaluate(types.PackageIdentity{Ecosystem: "npm", Name: "@company/package", Version: "1.0.0"}, []types.Reason{{ID: ruleID}}, nil, nil, nil, pol)
			got := ApplyPolicyControls(base, pol, "default", policy.RegistryConfig{URL: "https://registry.npmjs.org", Type: "public", Enabled: true}, "ai_agent", "ai_agent")
			if got.Decision != types.DecisionBlock {
				t.Fatalf("security rule %s was downgraded to %s: %+v", ruleID, got.Decision, got.Reasons)
			}
			if got.ExceptionInfo != nil && got.ExceptionInfo.Matched {
				t.Fatalf("security rule %s applied exception %+v", ruleID, got.ExceptionInfo)
			}
			if hasReason(got.Reasons, "trusted_package_reduction") {
				t.Fatalf("security rule %s received trust reduction", ruleID)
			}
		})
	}
}

func TestControlledExceptionMayDowngradeOrdinaryRiskBlock(t *testing.T) {
	pol := invariantPolicy("ordinary-package")
	pol.TrustedPackageRules = nil
	base := Evaluate(types.PackageIdentity{Ecosystem: "npm", Name: "ordinary-package", Version: "1.0.0"}, []types.Reason{{ID: "known_vulnerability_critical"}}, nil, nil, nil, pol)
	got := ApplyPolicyControls(base, pol, "default", policy.RegistryConfig{URL: "https://registry.npmjs.org", Type: "public", Enabled: true}, "human", "developer")
	if got.Decision != types.DecisionWarn {
		t.Fatalf("ordinary policy block should follow controlled exception, got %s: %+v", got.Decision, got.Reasons)
	}
	if got.ExceptionInfo == nil || !got.ExceptionInfo.Matched {
		t.Fatal("expected active controlled exception evidence")
	}
}

func invariantPolicy(name string) policy.Policy {
	pol := policy.Default()
	pol.TrustedPackageRules = []policy.TrustedPackageRule{{Name: name, VersionRange: "*", Registry: "default", Reason: "test trust"}}
	pol.Exceptions = []policy.Exception{{
		ID:           "EXC-SECURITY-MATRIX",
		Ecosystem:    "npm",
		Package:      name,
		VersionRange: "*",
		AllowedUntil: time.Now().Add(time.Hour),
		ApprovedBy:   "security@example.test",
		Reason:       "test controlled exception",
	}}
	pol.AgentPolicy.AllowAgentExceptions = true
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"private": {URL: "https://npm.company.test", Type: "private", Enabled: true, Scopes: []string{"@company"}},
		},
	}
	return pol
}
