package ci

import "github.com/niyam-ai/pkgsafe/internal/types"

type SandboxSummary struct {
	Enabled               bool `json:"enabled"`
	Available             bool `json:"available"`
	CriticalFindingsCount int  `json:"critical_findings_count"`
}

type Finding struct {
	Ecosystem         string                `json:"ecosystem"`
	Package           string                `json:"package"`
	Version           string                `json:"version"`
	Decision          string                `json:"decision"`
	RiskScore         int                   `json:"risk_score"`
	Direct            bool                  `json:"direct"`
	DependencyType    string                `json:"dependency_type"`
	Reasons           []types.Reason        `json:"reasons"`
	Vulnerabilities   []types.Vulnerability `json:"vulnerabilities"`
	Sandbox           SandboxSummary        `json:"sandbox"`
	RecommendedAction string                `json:"recommended_action"`
}

type Summary struct {
	PackagesScanned int `json:"packages_scanned"`
	Allow           int `json:"allow"`
	Warn            int `json:"warn"`
	Block           int `json:"block"`
}

type ScanResult struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Command       string    `json:"command"`
	Mode          string    `json:"mode"`
	FailOn        string    `json:"fail_on"`
	Decision      string    `json:"decision"`
	Lockfile      string    `json:"lockfile"`
	ChangedOnly   bool      `json:"changed_only"`
	Baseline      string    `json:"baseline"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}
