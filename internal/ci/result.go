package ci

import "github.com/niyam-ai/pkgsafe/internal/types"

type SandboxSummary struct {
	Enabled               bool `json:"enabled"`
	Available             bool `json:"available"`
	CriticalFindingsCount int  `json:"critical_findings_count"`
}

type Finding struct {
	Ecosystem         string                   `json:"ecosystem"`
	Package           string                   `json:"package"`
	Version           string                   `json:"version"`
	Decision          string                   `json:"decision"`
	RiskScore         int                      `json:"risk_score"`
	Direct            bool                     `json:"direct"`
	DependencyType    string                   `json:"dependency_type"`
	Reasons           []types.Reason           `json:"reasons"`
	Vulnerabilities   []types.Vulnerability    `json:"vulnerabilities"`
	Sandbox           SandboxSummary           `json:"sandbox"`
	RecommendedAction string                   `json:"recommended_action"`
	Policy            *types.PolicyEvidence    `json:"policy,omitempty"`
	Registry          *types.RegistryEvidence  `json:"registry,omitempty"`
	Trust             *types.TrustEvidence     `json:"trust,omitempty"`
	Exception         *types.ExceptionEvidence `json:"exception,omitempty"`
}

type Summary struct {
	PackagesScanned int `json:"packages_scanned"`
	Allow           int `json:"allow"`
	Warn            int `json:"warn"`
	Block           int `json:"block"`
	Unknown         int `json:"unknown"`
}

type ScanResult struct {
	SchemaVersion     string    `json:"schema_version"`
	Tool              string    `json:"tool"`
	Command           string    `json:"command"`
	Mode              string    `json:"mode"`
	FailOn            string    `json:"fail_on"`
	Decision          string    `json:"decision"`
	Lockfile          string    `json:"lockfile"`
	DependencyFiles   []string  `json:"dependency_files,omitempty"`
	Ecosystem         string    `json:"ecosystem,omitempty"`
	ChangedOnly       bool      `json:"changed_only"`
	Baseline          string    `json:"baseline"`
	Summary           Summary   `json:"summary"`
	Findings          []Finding `json:"findings"`
	PolicyPack        string    `json:"policy_pack,omitempty"`
	PolicyPackVersion string    `json:"policy_pack_version,omitempty"`
	ExceptionsUsed    []string  `json:"exceptions_used,omitempty"`
}
