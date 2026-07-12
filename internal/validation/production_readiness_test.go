package validation

import (
	"bytes"
	"encoding/json"
	"testing"
)

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
		OnlineBenchmarkStatus:       "pass",
		GitHubActionStatus:          "valid",
		SignedReleaseStatus:         "signed",
		SigningVerified:             true,
		SBOMStatus:                  "present",
		SBOMVerified:                true,
		ChecksumsStatus:             "verified",
		ChecksumsVerified:           true,
		ProvenanceStatus:            "verified",
		ProvenanceVerified:          true,
		DocsStatus:                  "complete",
		RealRepoValidationCount:     15,
		RepoValidationPassRate:      1,
		NPMRepoCount:                5,
		AverageScanDurationMs:       100,
		P95ScanDurationMs:           200,
		CriticalDetectionRate:       1,
		EcosystemDepthStatus:        "npm-public-beta-go-cargo-preview",
		IsolatedBackendStatus:       "unavailable",
		BehaviorAnalysisDefaultMode: "disabled",
	}
	computeReadinessStage(&rep, false)
	if rep.FinalStatus != ReadinessProductionGA {
		t.Errorf("expected PRODUCTION_GA_READY, got %q", rep.FinalStatus)
	}
	if rep.EcosystemDepthStatus != "npm-ga-go-cargo-preview" {
		t.Errorf("expected npm GA ecosystem status, got %q", rep.EcosystemDepthStatus)
	}
}

func TestProductionEcosystemDepthKeepsPyPIBeta(t *testing.T) {
	rep := ProductionReadinessReport{PyPIRepoCount: 3}
	if got := productionEcosystemDepthStatus(rep); got != "npm-ga-pypi-public-beta-go-cargo-preview" {
		t.Fatalf("expected npm-only GA with PyPI beta and Go/Cargo preview, got %q", got)
	}
}

func TestProductionReadinessGABlockedWhenRepoCountLow(t *testing.T) {
	rep := ProductionReadinessReport{
		OnlineBenchmarkStatus:       "pass",
		GitHubActionStatus:          "valid",
		SignedReleaseStatus:         "signed",
		SigningVerified:             true,
		SBOMStatus:                  "present",
		SBOMVerified:                true,
		ChecksumsStatus:             "verified",
		ChecksumsVerified:           true,
		ProvenanceStatus:            "verified",
		ProvenanceVerified:          true,
		DocsStatus:                  "complete",
		RealRepoValidationCount:     2,
		RepoValidationPassRate:      1,
		NPMRepoCount:                2,
		AverageScanDurationMs:       100,
		P95ScanDurationMs:           200,
		CriticalDetectionRate:       1,
		EcosystemDepthStatus:        "npm-public-beta-go-cargo-preview",
		IsolatedBackendStatus:       "unavailable",
		BehaviorAnalysisDefaultMode: "disabled",
	}
	computeReadinessStage(&rep, false)
	if rep.GAReady {
		t.Fatal("GA should be blocked when real repo count is below threshold")
	}
	if len(rep.GABlockers) == 0 {
		t.Fatal("expected GA blockers")
	}
}

func TestProductionReadinessJSONIncludesGAEvidenceFields(t *testing.T) {
	rep := ProductionReadinessReport{
		FinalStatus:                     ReadinessPrivateBeta,
		PrivateBetaReady:                true,
		GAReady:                         false,
		ProductionReady:                 false,
		RealRepoValidationCount:         0,
		RequiredRealRepoValidationCount: 15,
		RepoValidationPassRate:          0,
		RepoValidationFailures:          []string{"repo: dependency_inventory_error"},
		GABlockers:                      []string{"real_repo_validation_count below GA threshold"},
		EcosystemDepthStatus:            "npm-public-beta-go-cargo-preview",
		BehaviorAnalysisDefaultMode:     "disabled",
		IsolatedBackendAvailable:        false,
		SigningConfigured:               true,
		SigningVerified:                 false,
		ProvenanceConfigured:            true,
		ProvenanceVerified:              false,
		ChecksumsStatus:                 "verified",
		ChecksumsVerified:               true,
		SBOMStatus:                      "present",
		SBOMVerified:                    true,
	}
	var buf bytes.Buffer
	if err := WriteProductionReadiness(&buf, rep, true); err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"private_beta_ready",
		"ga_ready",
		"production_ready",
		"real_repo_validation_count",
		"required_real_repo_validation_count",
		"repo_validation_pass_rate",
		"repo_validation_failures",
		"ga_blockers",
		"ecosystem_depth_status",
		"behavior_analysis_default_mode",
		"isolated_backend_available",
		"signing_configured",
		"signing_verified",
		"provenance_configured",
		"provenance_verified",
		"checksums_status",
		"checksums_verified",
		"sbom_verified",
	} {
		if _, ok := got[field]; !ok {
			t.Fatalf("production readiness JSON missing %q: %s", field, buf.String())
		}
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

func TestBenchmarkValidationRejectsIneligibleAggregate(t *testing.T) {
	rep := BenchmarkReport{Pass: true, Status: "BENCHMARK_EVIDENCE_INELIGIBLE"}
	rep.Metrics.PackagesConfigured = 25
	rep.Metrics.PackagesExecuted = 1
	rep.Metrics.PackagesSkipped = 24
	rep.Metrics.PackageCoverageRatio = 0.04
	passed, _, _ := benchmarkValidationGate(rep, nil)
	if passed {
		t.Fatal("ineligible aggregate must fail the production readiness benchmark gate")
	}
}

func TestRealRepoEvidenceGateRequiresThresholdAndTiming(t *testing.T) {
	rep := BenchmarkReport{}
	if passed, _, _ := realRepoEvidenceGate(rep, nil, 15); passed {
		t.Fatal("zero repositories must fail")
	}
	rep.Metrics.RealRepoValidationCount = 15
	rep.Metrics.ReposPassed = 15
	if passed, _, _ := realRepoEvidenceGate(rep, nil, 15); passed {
		t.Fatal("missing trustworthy timing must fail")
	}
	rep.Metrics.RealRepoTimingTrustworthy = true
	if passed, _, _ := realRepoEvidenceGate(rep, nil, 15); !passed {
		t.Fatal("threshold, clean results, and trustworthy timing should pass")
	}
}

var errTest = errTestType("benchmark unavailable")

type errTestType string

func (e errTestType) Error() string { return string(e) }
