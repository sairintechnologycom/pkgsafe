package types

import "time"

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionBlock Decision = "block"
)

type Reason struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
	ScoreImpact int    `json:"score_impact"`
}

type PackageIdentity struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

type ScanResult struct {
	Package        PackageIdentity `json:"package"`
	Score          int             `json:"risk_score"`
	Decision       Decision        `json:"decision"`
	Reasons        []Reason        `json:"reasons"`
	Lifecycle      []string        `json:"lifecycle_scripts,omitempty"`
	Suspicious     []string        `json:"suspicious_patterns,omitempty"`
	SafeAlternates []string        `json:"safe_alternatives,omitempty"`
	ScannedAt      time.Time       `json:"scanned_at"`
}
