package risk

import (
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestApplyPolicyControlsAttachesPackageProfile(t *testing.T) {
	pol := policy.Default()
	res := types.ScanResult{
		Package: types.PackageIdentity{
			Ecosystem: "npm",
			Name:      "example",
			Version:   "1.2.3",
		},
		Decision:     types.DecisionWarn,
		Score:        42,
		Reasons:      []types.Reason{{ID: "typosquat_candidate", Description: "Package name resembles a popular package", ScoreImpact: 20}},
		Sandbox:      types.SandboxSummary{BehaviorMode: types.BehaviorHeuristic, Enabled: true, Available: true, Isolated: false, Runner: "host"},
		PolicyInfo:   &types.PolicyEvidence{Source: "local", Name: "default", Version: "1.0.0"},
		RegistryInfo: &types.RegistryEvidence{Name: "npmjs", URL: "https://registry.npmjs.org"},
	}

	out := ApplyPolicyControls(res, pol, "npmjs", policy.RegistryConfig{URL: "https://registry.npmjs.org"}, "human", "developer")
	if out.Profile.SchemaVersion != "1.0" {
		t.Fatalf("schema_version = %q, want 1.0", out.Profile.SchemaVersion)
	}
	if out.Profile.Package.Name != "example" || out.Profile.Package.ResolvedVersion != "1.2.3" {
		t.Fatalf("package profile not populated correctly: %+v", out.Profile.Package)
	}
	if out.Profile.Decision != out.Decision {
		t.Fatalf("profile decision %q does not match result decision %q", out.Profile.Decision, out.Decision)
	}
	if out.Profile.EvidenceID == "" {
		t.Fatal("expected evidence id to be populated")
	}
	if len(out.Profile.BehaviorSignals) != 1 {
		t.Fatalf("expected one behavior signal, got %d", len(out.Profile.BehaviorSignals))
	}
	if len(out.Profile.HardBlocks) != 0 {
		t.Fatalf("unexpected hard blocks: %+v", out.Profile.HardBlocks)
	}
	if len(out.Profile.TopReasons) == 0 {
		t.Fatal("expected top reasons to be populated")
	}
}
