package report

import "time"

// RepositoryMetadata contains details about the target Git repository.
type RepositoryMetadata struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	RemoteURL string `json:"remote_url,omitempty"`
	Branch    string `json:"branch,omitempty"`
	Commit    string `json:"commit,omitempty"`
	Dirty     bool   `json:"dirty"`
	LatestTag string `json:"latest_tag,omitempty"`
}

// PolicyMetadata contains details about the applied policy rules.
type PolicyMetadata struct {
	Source      string `json:"source"`
	PackName    string `json:"pack_name"`
	PackVersion string `json:"pack_version"`
	Owner       string `json:"owner"`
}

// RiskSummary lists count statistics for the scan findings.
type RiskSummary struct {
	PackagesScanned             int `json:"packages_scanned"`
	Allowed                     int `json:"allowed"`
	Warnings                    int `json:"warned"`
	Blocked                     int `json:"blocked"`
	Unknown                     int `json:"unknown"`
	CriticalVulnerabilities     int `json:"critical_vulnerabilities"`
	HighVulnerabilities         int `json:"high_vulnerabilities"`
	ActiveExceptions            int `json:"active_exceptions"`
	DeveloperOverrides          int `json:"overrides_used"`
	PrivateRegistryViolations   int `json:"private_registry_violations"`
	DependencyConfusionFindings int `json:"dependency_confusion_findings"`
}

// FindingEvidence holds information on where and why a risk was detected.
type FindingEvidence struct {
	Source   string `json:"source,omitempty"`
	Script   string `json:"script,omitempty"`
	Behavior string `json:"behavior,omitempty"`
}

// FindingPolicy outlines the rules used to reach a decision.
type FindingPolicy struct {
	Pack       string `json:"pack"`
	Version    string `json:"version"`
	RuleSource string `json:"rule_source"`
}

// FindingRegistry contains registry classification details.
type FindingRegistry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// FindingException details any matching exception rules.
type FindingException struct {
	Matched bool   `json:"matched"`
	ID      string `json:"id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// FindingOverride outlines whether a developer overrode a blocked package.
type FindingOverride struct {
	Used   bool   `json:"used"`
	Reason string `json:"reason,omitempty"`
}

// ReportFinding represents a single dependency evaluation entry.
type ReportFinding struct {
	FindingID         string           `json:"finding_id"`
	Ecosystem         string           `json:"ecosystem"`
	Package           string           `json:"package"`
	Version           string           `json:"version"`
	Decision          string           `json:"decision"`
	RiskScore         int              `json:"risk_score"`
	Severity          string           `json:"severity"`
	RuleID            string           `json:"rule_id"`
	Message           string           `json:"message"`
	Evidence          FindingEvidence  `json:"evidence"`
	Policy            FindingPolicy    `json:"policy"`
	Registry          FindingRegistry  `json:"registry"`
	Exception         FindingException `json:"exception"`
	Override          FindingOverride  `json:"override"`
	RecommendedAction string           `json:"recommended_action"`
}

// ExceptionRecord outlines a temporary risk exception.
type ExceptionRecord struct {
	ID                string    `json:"id"`
	Package           string    `json:"package"`
	Ecosystem         string    `json:"ecosystem"`
	VersionRange      string    `json:"version_range"`
	Reason            string    `json:"reason"`
	ApprovedBy        string    `json:"approved_by"`
	AllowedUntil      time.Time `json:"allowed_until"`
	DaysUntilExpiry   int       `json:"days_until_expiry"`
	Environments      []string  `json:"environments,omitempty"`
	UsedInRecentScans bool      `json:"used_in_recent_scans"`
	Status            string    `json:"status"` // Active or Expired
}

// OverrideRecord contains details of a user forced override.
type OverrideRecord struct {
	Timestamp        string `json:"timestamp"`
	User             string `json:"user"`
	Repository       string `json:"repository"`
	Command          string `json:"command"`
	Package          string `json:"package"`
	Ecosystem        string `json:"ecosystem"`
	Version          string `json:"version"`
	Decision         string `json:"decision"`
	RiskScore        int    `json:"risk_score"`
	OverrideReason   string `json:"override_reason"`
	PolicyPack       string `json:"policy_pack"`
	AllowedByPolicy  bool   `json:"allowed_by_policy"`
	MalwareAttempted bool   `json:"malware_attempted"`
}

// RegistryRecord documents registry enforcement and validation results.
type RegistryRecord struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	Type            string   `json:"type"`
	Enabled         bool     `json:"enabled"`
	Scopes          []string `json:"scopes,omitempty"`
	Prefixes        []string `json:"prefixes,omitempty"`
	AuthMethod      string   `json:"auth_method"`
	TestStatus      string   `json:"test_status,omitempty"`
	ResolutionCount int      `json:"resolution_count"`
	MismatchBlocks  int      `json:"mismatch_blocks"`
}

// RecommendationRecord provides recommended actions to improve security posture.
type RecommendationRecord struct {
	FindingID string `json:"finding_id,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	Type      string `json:"type"`
	Message   string `json:"message"`
}

// RepositoryRiskReport is the root report containing all collected evidence.
type RepositoryRiskReport struct {
	SchemaVersion   string                 `json:"schema_version"`
	Tool            string                 `json:"tool"`
	ReportType      string                 `json:"report_type"`
	GeneratedAt     string                 `json:"generated_at"`
	Repository      RepositoryMetadata     `json:"repository"`
	Policy          PolicyMetadata         `json:"policy"`
	Summary         RiskSummary            `json:"summary"`
	Findings        []ReportFinding        `json:"findings"`
	Exceptions      []ExceptionRecord      `json:"exceptions"`
	Overrides       []OverrideRecord       `json:"overrides"`
	Registries      []RegistryRecord       `json:"registries"`
	Recommendations []RecommendationRecord `json:"recommendations"`
}

// SIEMEvent represents a normalized SIEM alert event.
type SIEMEvent struct {
	Timestamp  string `json:"timestamp"`
	EventType  string `json:"event_type"`
	Severity   string `json:"severity"`
	Tool       string `json:"tool"`
	Ecosystem  string `json:"ecosystem,omitempty"`
	Package    string `json:"package,omitempty"`
	Version    string `json:"version,omitempty"`
	Decision   string `json:"decision,omitempty"`
	RiskScore  int    `json:"risk_score,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Repository string `json:"repository,omitempty"`
	PolicyPack string `json:"policy_pack,omitempty"`
	Message    string `json:"message"`
}
