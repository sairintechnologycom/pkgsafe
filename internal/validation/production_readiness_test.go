package validation

import "testing"

func TestComputeReadinessStageBlocked(t *testing.T) {
	rep := ProductionReadinessReport{}
	computeReadinessStage(&rep, true)
	if rep.FinalStatus != ReadinessBlocked {
		t.Errorf("blocking failure should be BLOCKED, got %q", rep.FinalStatus)
	}
	if rep.Pass {
		t.Error("blocked report should not pass")
	}
	if rep.PrivateBetaRecommendation {
		t.Error("blocked report should not recommend private beta")
	}
}

func TestComputeReadinessStagePrivateBetaIsConservative(t *testing.T) {
	// Foundation gates passed, but GA hardening is only configured (not
	// verified): must cap at PRIVATE_BETA_READY.
	rep := ProductionReadinessReport{
		OnlineBenchmarkStatus:   "no_network",
		GitHubActionStatus:      "valid",
		SignedReleaseStatus:     "configured",
		SBOMStatus:              "present",
		ProvenanceStatus:        "configured",
		DocsStatus:              "complete",
		RealRepoValidationCount: 0,
	}
	computeReadinessStage(&rep, false)
	if rep.FinalStatus != ReadinessPrivateBeta {
		t.Errorf("expected PRIVATE_BETA_READY, got %q", rep.FinalStatus)
	}
	if !rep.Pass || !rep.PrivateBetaRecommendation {
		t.Error("private beta should pass and be recommended")
	}
}

func TestComputeReadinessStagePublicBeta(t *testing.T) {
	rep := ProductionReadinessReport{
		OnlineBenchmarkStatus:   "pass",
		GitHubActionStatus:      "valid",
		SignedReleaseStatus:     "configured",
		SBOMStatus:              "present",
		ProvenanceStatus:        "configured",
		DocsStatus:              "complete",
		RealRepoValidationCount: 1,
	}
	computeReadinessStage(&rep, false)
	if rep.FinalStatus != ReadinessPublicBeta {
		t.Errorf("expected PUBLIC_BETA_READY, got %q", rep.FinalStatus)
	}
}

func TestComputeReadinessStageProductionGA(t *testing.T) {
	rep := ProductionReadinessReport{
		OnlineBenchmarkStatus:   "pass",
		GitHubActionStatus:      "valid",
		SignedReleaseStatus:     "signed",
		SBOMStatus:              "present",
		ProvenanceStatus:        "verified",
		DocsStatus:              "complete",
		RealRepoValidationCount: 3,
	}
	computeReadinessStage(&rep, false)
	if rep.FinalStatus != ReadinessProductionGA {
		t.Errorf("expected PRODUCTION_GA_READY, got %q", rep.FinalStatus)
	}
}

func TestOnlineBenchmarkStatusIsExplicit(t *testing.T) {
	// An errored or empty benchmark must never be reported as a silent pass.
	if got := onlineBenchmarkStatus(BenchmarkReport{}, errTest); got != "error" {
		t.Errorf("benchmark error should map to error, got %q", got)
	}
	if got := onlineBenchmarkStatus(BenchmarkReport{}, nil); got != "not_run" {
		t.Errorf("empty online summary should map to not_run, got %q", got)
	}
	rep := BenchmarkReport{Online: OnlineBenchmarkSummary{Status: "no_network"}}
	if got := onlineBenchmarkStatus(rep, nil); got != "no_network" {
		t.Errorf("expected no_network, got %q", got)
	}
}

var errTest = errTestType("benchmark unavailable")

type errTestType string

func (e errTestType) Error() string { return string(e) }
