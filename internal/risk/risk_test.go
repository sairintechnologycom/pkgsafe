package risk

import (
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestScoreClampingAbove100(t *testing.T) {
	res := Evaluate(pkg("danger"), []types.Reason{
		{ID: "credential_path_reference", Description: "credential path"},
		{ID: "secret_keyword_reference", Description: "secret keyword"},
	}, nil, nil, nil, policy.Default())
	if res.Score != 100 {
		t.Fatalf("expected score clamped to 100, got %d", res.Score)
	}
}

func TestScoreClampingBelow0(t *testing.T) {
	res := Evaluate(pkg("axios"), nil, nil, nil, nil, policy.Default())
	if res.Score != 0 {
		t.Fatalf("expected score clamped to 0, got %d", res.Score)
	}
}

func TestTrustedPackageReducesScore(t *testing.T) {
	res := Evaluate(pkg("axios"), []types.Reason{{ID: "lifecycle_script_present", Description: "script"}}, nil, nil, nil, policy.Default())
	if res.Score != 0 {
		t.Fatalf("expected trusted package reduction to lower score to 0, got %d reasons=%v", res.Score, res.Reasons)
	}
	if !hasReason(res.Reasons, "trusted_package_reduction") {
		t.Fatalf("expected trusted reduction reason: %v", res.Reasons)
	}
}

func TestTrustedPackageDoesNotOverrideCredentialRisk(t *testing.T) {
	res := Evaluate(pkg("axios"), []types.Reason{{ID: "credential_path_reference", Description: "credential path"}}, nil, nil, nil, policy.Default())
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected credential risk to block trusted package, got %s", res.Decision)
	}
	if hasReason(res.Reasons, "trusted_package_reduction") {
		t.Fatalf("trusted reduction should not apply to critical findings: %v", res.Reasons)
	}
}

func TestBlockedPackageAlwaysBlocks(t *testing.T) {
	pol := policy.Default()
	pol.BlockedPackages.NPM = []string{"left-pad"}
	res := Evaluate(pkg("left-pad"), nil, nil, nil, nil, pol)
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected blocked package to block, got %s", res.Decision)
	}
}

func TestLifecycleScriptAddsConfiguredScore(t *testing.T) {
	pol := policy.Default()
	rule := pol.Rules["lifecycle_script_present"]
	rule.Score = 42
	pol.Rules["lifecycle_script_present"] = rule
	res := Evaluate(pkg("custom"), []types.Reason{{ID: "lifecycle_script_present", Description: "script"}}, nil, nil, nil, pol)
	if res.Score != 42 {
		t.Fatalf("expected configured score 42, got %d", res.Score)
	}
}

func TestDisabledRuleDoesNotAffectScore(t *testing.T) {
	pol := policy.Default()
	rule := pol.Rules["lifecycle_script_present"]
	rule.Enabled = false
	pol.Rules["lifecycle_script_present"] = rule
	res := Evaluate(pkg("custom"), []types.Reason{{ID: "lifecycle_script_present", Description: "script"}}, nil, nil, nil, pol)
	if res.Score != 0 || len(res.Reasons) != 0 {
		t.Fatalf("expected disabled rule to have no effect, got score=%d reasons=%v", res.Score, res.Reasons)
	}
}

func TestCredentialPathReferenceCausesBlock(t *testing.T) {
	res := Evaluate(pkg("custom"), []types.Reason{{ID: "credential_path_reference", Description: "credential path"}}, nil, nil, nil, policy.Default())
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected credential path to block, got %s", res.Decision)
	}
}

func TestDecisionThresholdsWork(t *testing.T) {
	pol := policy.Default()
	pol.Thresholds.AllowMaxScore = 10
	pol.Thresholds.WarnMaxScore = 20
	pol.Thresholds.BlockMinScore = 21
	rule := pol.Rules["missing_repository"]
	rule.Score = 15
	pol.Rules["missing_repository"] = rule
	res := Evaluate(pkg("custom"), []types.Reason{{ID: "missing_repository", Description: "missing repo"}}, nil, nil, nil, pol)
	if res.Decision != types.DecisionWarn {
		t.Fatalf("expected warn threshold decision, got %s", res.Decision)
	}
	rule.Score = 21
	pol.Rules["missing_repository"] = rule
	res = Evaluate(pkg("custom"), []types.Reason{{ID: "missing_repository", Description: "missing repo"}}, nil, nil, nil, pol)
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected block threshold decision, got %s", res.Decision)
	}
}

func TestAuditModeNeverEnforcesBlock(t *testing.T) {
	pol := policy.Default()
	pol.Mode = policy.ModeAudit
	res := Evaluate(pkg("custom"), []types.Reason{{ID: "credential_path_reference", Description: "credential path"}}, nil, nil, nil, pol)
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected decision to report block risk, got %s", res.Decision)
	}
	if res.Enforcement != "Not blocked" {
		t.Fatalf("expected audit enforcement not blocked, got %q", res.Enforcement)
	}
}

func pkg(name string) types.PackageIdentity {
	return types.PackageIdentity{Ecosystem: "npm", Name: name, Version: "1.0.0"}
}

func hasReason(reasons []types.Reason, id string) bool {
	for _, reason := range reasons {
		if reason.ID == id {
			return true
		}
	}
	return false
}
