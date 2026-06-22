package types

import "time"

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionBlock Decision = "block"
)

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
	Aliases       []string `json:"aliases,omitempty"`
	Severity      string   `json:"severity"`
	Summary       string   `json:"summary"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	References    []string `json:"references,omitempty"`
}

type ScanResult struct {
	Package         PackageIdentity `json:"package"`
	Mode            string          `json:"mode,omitempty"`
	Score           int             `json:"risk_score"`
	Decision        Decision        `json:"decision"`
	Thresholds      Thresholds      `json:"thresholds,omitempty"`
	Reasons         []Reason        `json:"reasons"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Lifecycle       []string        `json:"lifecycle_scripts,omitempty"`
	Suspicious      []string        `json:"suspicious_patterns,omitempty"`
	SafeAlternates  []string        `json:"safe_alternatives,omitempty"`
	Enforcement     string          `json:"enforcement,omitempty"`
	Recommended     string          `json:"recommended_action,omitempty"`
	ScannedAt       time.Time       `json:"scanned_at"`
	Sandbox         SandboxSummary  `json:"sandbox,omitempty"`
}

type SandboxSummary struct {
	Enabled         bool                  `json:"enabled"`
	Available       bool                  `json:"available"`
	Runner          string                `json:"runner,omitempty"`
	NetworkMode     string                `json:"network_mode,omitempty"`
	TimeoutSeconds  int                   `json:"timeout_seconds,omitempty"`
	ScriptsExecuted []SandboxScriptResult `json:"scripts_executed,omitempty"`
	NotPerformed    bool                  `json:"-"`
	NotPerfReason   string                `json:"-"`
}

type SandboxScriptResult struct {
	Name       string           `json:"name"`
	ExitCode   int              `json:"exit_code"`
	TimedOut   bool             `json:"timed_out"`
	DurationMs int64            `json:"duration_ms"`
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
