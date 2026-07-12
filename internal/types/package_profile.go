package types

// PackageProfile is the canonical package assessment object shared by the
// scanner, CLI, MCP, and evidence outputs.
type PackageProfile struct {
	SchemaVersion   string                  `json:"schema_version"`
	Package         PackageProfileIdentity  `json:"package"`
	Decision        Decision                `json:"decision"`
	RiskScore       int                     `json:"risk_score"`
	Confidence      string                  `json:"confidence"`
	HardBlocks      []string                `json:"hard_blocks,omitempty"`
	TopReasons      []string                `json:"top_reasons,omitempty"`
	Vulnerabilities []Vulnerability         `json:"vulnerabilities,omitempty"`
	BehaviorSignals []PackageBehaviorSignal `json:"behavior_signals,omitempty"`
	IdentityRisk    PackageRiskFacet        `json:"identity_risk,omitempty"`
	RegistryRisk    PackageRiskFacet        `json:"registry_risk,omitempty"`
	Provenance      PackageProvenance       `json:"provenance,omitempty"`
	Policy          PackageProfilePolicy    `json:"policy,omitempty"`
	Remediation     []string                `json:"remediation,omitempty"`
	EvidenceID      string                  `json:"evidence_id"`
}

type PackageProfileIdentity struct {
	Ecosystem        string `json:"ecosystem"`
	Name             string `json:"name"`
	RequestedVersion string `json:"requested_version,omitempty"`
	ResolvedVersion  string `json:"resolved_version,omitempty"`
	Registry         string `json:"registry,omitempty"`
}

type PackageBehaviorSignal struct {
	Mode          BehaviorMode `json:"mode"`
	Executed      bool         `json:"executed"`
	Isolated      bool         `json:"isolated"`
	Runner        string       `json:"runner,omitempty"`
	NetworkPolicy string       `json:"network_policy,omitempty"`
	Warning       string       `json:"warning,omitempty"`
	NotPerformed  bool         `json:"not_performed,omitempty"`
	Reason        string       `json:"reason,omitempty"`
	Limitations   []string     `json:"limitations,omitempty"`
}

type PackageRiskFacet struct {
	Score   int      `json:"score,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	Signals []string `json:"signals,omitempty"`
}

type PackageProvenance struct {
	ScannedAt     string `json:"scanned_at,omitempty"`
	PolicySource  string `json:"policy_source,omitempty"`
	PolicyName    string `json:"policy_name,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	Registry      string `json:"registry,omitempty"`
}

type PackageProfilePolicy struct {
	Mode              string     `json:"mode,omitempty"`
	Thresholds        Thresholds `json:"thresholds,omitempty"`
	Enforcement       string     `json:"enforcement,omitempty"`
	RecommendedAction string     `json:"recommended_action,omitempty"`
}
