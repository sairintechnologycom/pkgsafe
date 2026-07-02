package types

import (
	"encoding/json"
	"time"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionBlock Decision = "block"
	// DecisionUnknown marks a package that could not be scanned (e.g. offline
	// with no cached result). It must never be treated as a clean pass.
	DecisionUnknown Decision = "unknown"
)

type BehaviorMode string

const (
	BehaviorDisabled  BehaviorMode = "disabled"
	BehaviorHeuristic BehaviorMode = "heuristic"
	BehaviorIsolated  BehaviorMode = "isolated"
)

func NormalizeBehaviorMode(mode string, legacyEnabled bool) BehaviorMode {
	switch BehaviorMode(mode) {
	case BehaviorDisabled, BehaviorHeuristic, BehaviorIsolated:
		return BehaviorMode(mode)
	}
	if legacyEnabled {
		return BehaviorHeuristic
	}
	return BehaviorDisabled
}

type Reason struct {
	ID          string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"message"`
	Evidence    string `json:"evidence,omitempty"`
	ScoreImpact int    `json:"score"`
}

type PackageIdentity struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

type Vulnerability struct {
	ID            string   `json:"id"`
	Source        string   `json:"source,omitempty"`
	Ecosystem     string   `json:"ecosystem,omitempty"`
	PackageName   string   `json:"package_name,omitempty"`
	Version       string   `json:"version,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	Severity      string   `json:"severity"`
	Summary       string   `json:"summary"`
	Details       string   `json:"details,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	References    []string `json:"references,omitempty"`
	PublishedAt   string   `json:"published_at,omitempty"`
	ModifiedAt    string   `json:"modified_at,omitempty"`
	FetchedAt     string   `json:"fetched_at,omitempty"`
}

type ScanResult struct {
	Package         PackageIdentity    `json:"package"`
	Mode            string             `json:"mode,omitempty"`
	Score           int                `json:"risk_score"`
	Decision        Decision           `json:"decision"`
	Thresholds      Thresholds         `json:"thresholds,omitempty"`
	Reasons         []Reason           `json:"reasons"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities,omitempty"`
	Lifecycle       []string           `json:"lifecycle_scripts,omitempty"`
	Suspicious      []string           `json:"suspicious_patterns,omitempty"`
	SafeAlternates  []string           `json:"safe_alternatives,omitempty"`
	Enforcement     string             `json:"enforcement,omitempty"`
	Recommended     string             `json:"recommended_action,omitempty"`
	ScannedAt       time.Time          `json:"scanned_at"`
	Sandbox         SandboxSummary     `json:"behavior_analysis,omitempty"`
	Artifact        ArtifactSummary    `json:"artifact_analysis,omitempty"`
	PolicyInfo      *PolicyEvidence    `json:"policy,omitempty"`
	RegistryInfo    *RegistryEvidence  `json:"registry,omitempty"`
	TrustInfo       *TrustEvidence     `json:"trust,omitempty"`
	ExceptionInfo   *ExceptionEvidence `json:"exception,omitempty"`
}

func (r ScanResult) MarshalJSON() ([]byte, error) {
	type scanResultJSON struct {
		Package          PackageIdentity         `json:"package"`
		Mode             string                  `json:"mode,omitempty"`
		Score            int                     `json:"risk_score"`
		Decision         Decision                `json:"decision"`
		Thresholds       Thresholds              `json:"thresholds,omitempty"`
		Reasons          []Reason                `json:"reasons"`
		Vulnerabilities  []Vulnerability         `json:"vulnerabilities,omitempty"`
		Lifecycle        []string                `json:"lifecycle_scripts,omitempty"`
		Suspicious       []string                `json:"suspicious_patterns,omitempty"`
		SafeAlternates   []string                `json:"safe_alternatives,omitempty"`
		Enforcement      string                  `json:"enforcement,omitempty"`
		Recommended      string                  `json:"recommended_action,omitempty"`
		ScannedAt        time.Time               `json:"scanned_at"`
		BehaviorAnalysis BehaviorAnalysisSummary `json:"behavior_analysis,omitempty"`
		Artifact         ArtifactSummary         `json:"artifact_analysis,omitempty"`
		PolicyInfo       *PolicyEvidence         `json:"policy,omitempty"`
		RegistryInfo     *RegistryEvidence       `json:"registry,omitempty"`
		TrustInfo        *TrustEvidence          `json:"trust,omitempty"`
		ExceptionInfo    *ExceptionEvidence      `json:"exception,omitempty"`
	}
	return json.Marshal(scanResultJSON{
		Package:          r.Package,
		Mode:             r.Mode,
		Score:            r.Score,
		Decision:         r.Decision,
		Thresholds:       r.Thresholds,
		Reasons:          r.Reasons,
		Vulnerabilities:  r.Vulnerabilities,
		Lifecycle:        r.Lifecycle,
		Suspicious:       r.Suspicious,
		SafeAlternates:   r.SafeAlternates,
		Enforcement:      r.Enforcement,
		Recommended:      r.Recommended,
		ScannedAt:        r.ScannedAt,
		BehaviorAnalysis: BehaviorAnalysisFromSandbox(r.Sandbox),
		Artifact:         r.Artifact,
		PolicyInfo:       r.PolicyInfo,
		RegistryInfo:     r.RegistryInfo,
		TrustInfo:        r.TrustInfo,
		ExceptionInfo:    r.ExceptionInfo,
	})
}

type PolicyEvidence struct {
	Source  string `json:"source"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Owner   string `json:"owner"`
}

type RegistryEvidence struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	URL        string `json:"url"`
	AuthMethod string `json:"auth_method"`
}

type TrustEvidence struct {
	Matched bool   `json:"matched"`
	RuleID  string `json:"rule_id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type ExceptionEvidence struct {
	Matched    bool   `json:"matched"`
	RuleID     string `json:"rule_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	ValidUntil string `json:"valid_until,omitempty"`
}

type ArtifactSummary struct {
	WheelAvailable              bool   `json:"wheel_available"`
	SourceDistributionAvailable bool   `json:"source_distribution_available"`
	Yanked                      bool   `json:"yanked"`
	BuildBackend                string `json:"build_backend,omitempty"`
	BuildBackendPath            string `json:"build_backend_path,omitempty"`
	SetupPyPresent              bool   `json:"setup_py_present"`
	NativeExtension             bool   `json:"native_extension"`
	OrphanedBytecode            bool   `json:"orphaned_bytecode,omitempty"`
	SandboxNote                 string `json:"behavior_analysis_note,omitempty"`
}

type SandboxSummary struct {
	Enabled         bool                  `json:"enabled"`
	Available       bool                  `json:"available"`
	BehaviorMode    BehaviorMode          `json:"behavior_mode,omitempty"`
	Isolated        bool                  `json:"isolated"`
	Runner          string                `json:"runner,omitempty"`
	NetworkMode     string                `json:"network_mode,omitempty"`
	TimeoutSeconds  int                   `json:"timeout_seconds,omitempty"`
	ScriptsExecuted []SandboxScriptResult `json:"scripts_executed,omitempty"`
	Warning         string                `json:"warning,omitempty"`
	NotPerformed    bool                  `json:"not_performed,omitempty"`
	NotPerfReason   string                `json:"not_performed_reason,omitempty"`
}

type BehaviorAnalysisSummary struct {
	Mode          BehaviorMode          `json:"mode"`
	Enabled       bool                  `json:"enabled"`
	Executed      bool                  `json:"executed"`
	Isolated      bool                  `json:"isolated"`
	Runner        string                `json:"runner,omitempty"`
	NetworkPolicy string                `json:"network_policy,omitempty"`
	NotPerformed  bool                  `json:"not_performed"`
	Reason        string                `json:"reason,omitempty"`
	Warning       string                `json:"warning,omitempty"`
	Limitations   []string              `json:"limitations,omitempty"`
	Scripts       []SandboxScriptResult `json:"scripts,omitempty"`
}

func BehaviorAnalysisFromSandbox(s SandboxSummary) BehaviorAnalysisSummary {
	mode := s.BehaviorMode
	if mode == "" {
		mode = BehaviorDisabled
	}
	out := BehaviorAnalysisSummary{
		Mode:          mode,
		Enabled:       s.Enabled,
		Executed:      len(s.ScriptsExecuted) > 0,
		Isolated:      s.Isolated,
		Runner:        s.Runner,
		NetworkPolicy: s.NetworkMode,
		NotPerformed:  s.NotPerformed,
		Reason:        s.NotPerfReason,
		Warning:       s.Warning,
		Scripts:       s.ScriptsExecuted,
	}
	switch mode {
	case BehaviorDisabled:
		out.NotPerformed = true
		if out.Reason == "" {
			out.Reason = "behavior analysis disabled by policy"
		}
	case BehaviorHeuristic:
		out.Limitations = append(out.Limitations,
			"non-isolated host runner",
			"not a security sandbox",
			"network policy is advisory unless an isolated backend is active",
		)
	case BehaviorIsolated:
		if !s.Available {
			out.NotPerformed = true
			if out.Reason == "" {
				out.Reason = "isolated behavior analysis backend is unavailable"
			}
		}
	}
	return out
}

type SandboxScriptResult struct {
	Name       string           `json:"name"`
	ExitCode   int              `json:"exit_code"`
	TimedOut   bool             `json:"timed_out"`
	DurationMs int64            `json:"duration_ms"`
	Runner     string           `json:"runner,omitempty"`
	Isolated   bool             `json:"isolated"`
	Trace      []string         `json:"trace,omitempty"`
	Findings   []SandboxFinding `json:"findings,omitempty"`
}

type SandboxFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	Description string `json:"message"`
}

type Thresholds struct {
	AllowMaxScore int `json:"allow_max_score"`
	WarnMaxScore  int `json:"warn_max_score"`
	BlockMinScore int `json:"block_min_score"`
}
