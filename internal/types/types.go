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

type ScanResult struct {
	Package        PackageIdentity `json:"package"`
	Mode           string          `json:"mode,omitempty"`
	Score          int             `json:"risk_score"`
	Decision       Decision        `json:"decision"`
	Thresholds     Thresholds      `json:"thresholds,omitempty"`
	Reasons        []Reason        `json:"reasons"`
	Lifecycle      []string        `json:"lifecycle_scripts,omitempty"`
	Suspicious     []string        `json:"suspicious_patterns,omitempty"`
	SafeAlternates []string        `json:"safe_alternatives,omitempty"`
	Enforcement    string          `json:"enforcement,omitempty"`
	Recommended    string          `json:"recommended_action,omitempty"`
	ScannedAt      time.Time       `json:"scanned_at"`
}

type Thresholds struct {
	AllowMaxScore int `json:"allow_max_score"`
	WarnMaxScore  int `json:"warn_max_score"`
	BlockMinScore int `json:"block_min_score"`
}
