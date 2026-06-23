package policy

import (
	"time"
)

type RegistryAuth struct {
	Method      string `yaml:"method" json:"method"`
	TokenEnv    string `yaml:"token_env" json:"token_env"`
	UsernameEnv string `yaml:"username_env" json:"username_env"`
	PasswordEnv string `yaml:"password_env" json:"password_env"`
}

type RegistryTrust struct {
	TrustPrivateScope  bool `yaml:"trust_private_scope" json:"trust_private_scope"`
	RequireScopeMatch  bool `yaml:"require_scope_match" json:"require_scope_match"`
	TrustPrivatePrefix bool `yaml:"trust_private_prefix" json:"trust_private_prefix"`
	RequirePrefixMatch bool `yaml:"require_prefix_match" json:"require_prefix_match"`
}

type RegistryConfig struct {
	URL             string        `yaml:"url" json:"url"`
	SimpleURL       string        `yaml:"simple_url" json:"simple_url"`
	Type            string        `yaml:"type" json:"type"` // public, private
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	Scopes          []string      `yaml:"scopes" json:"scopes"`
	PackagePrefixes []string      `yaml:"package_prefixes" json:"package_prefixes"`
	Auth            RegistryAuth  `yaml:"auth" json:"auth"`
	Trust           RegistryTrust `yaml:"trust" json:"trust"`
}

type RegistriesConfig struct {
	Registries map[string]map[string]RegistryConfig `yaml:"registries" json:"registries"`
}

type TrustedPackageRule struct {
	Name         string     `yaml:"name" json:"name"`
	VersionRange string     `yaml:"version_range" json:"version_range"`
	Registry     string     `yaml:"registry" json:"registry"`
	Reason       string     `yaml:"reason" json:"reason"`
	Owner        string     `yaml:"owner" json:"owner"`
	ExpiresAt    *time.Time `yaml:"expires_at" json:"expires_at"`
}

type BlockedPackageRule struct {
	Name         string     `yaml:"name" json:"name"`
	VersionRange string     `yaml:"version_range" json:"version_range"`
	Registry     string     `yaml:"registry" json:"registry"`
	Reason       string     `yaml:"reason" json:"reason"`
	Severity     string     `yaml:"severity" json:"severity"`
	Owner        string     `yaml:"owner" json:"owner"`
	ExpiresAt    *time.Time `yaml:"expires_at" json:"expires_at"`
}

type TrustedPackagesConfig struct {
	TrustedPackages map[string][]TrustedPackageRule `yaml:"trusted_packages" json:"trusted_packages"`
}

type BlockedPackagesConfig struct {
	BlockedPackages map[string][]BlockedPackageRule `yaml:"blocked_packages" json:"blocked_packages"`
}

type AppliesTo struct {
	Repositories []string `yaml:"repositories" json:"repositories"`
	Environments []string `yaml:"environments" json:"environments"`
}

type Exception struct {
	ID                 string    `yaml:"id" json:"id"`
	Ecosystem          string    `yaml:"ecosystem" json:"ecosystem"`
	Package            string    `yaml:"package" json:"package"`
	VersionRange       string    `yaml:"version_range" json:"version_range"`
	AllowedUntil       time.Time `yaml:"allowed_until" json:"allowed_until"`
	ApprovedBy         string    `yaml:"approved_by" json:"approved_by"`
	Reason             string    `yaml:"reason" json:"reason"`
	MaxDecisionAllowed string    `yaml:"max_decision_allowed" json:"max_decision_allowed"`
	AppliesTo          AppliesTo `yaml:"applies_to" json:"applies_to"`
}

type ExceptionsConfig struct {
	Exceptions []Exception `yaml:"exceptions" json:"exceptions"`
}

type ScopedRuleMatch struct {
	Ecosystem      string `yaml:"ecosystem" json:"ecosystem"`
	Package        string `yaml:"package" json:"package"`
	Registry       string `yaml:"registry" json:"registry"`
	RequestedBy    string `yaml:"requested_by" json:"requested_by"`
	DependencyType string `yaml:"dependency_type" json:"dependency_type"`
}

type ScopedRuleApply struct {
	TrustScoreDelta         int  `yaml:"trust_score_delta" json:"trust_score_delta"`
	RequireRegistryMatch    bool `yaml:"require_registry_match" json:"require_registry_match"`
	WarnInstallAllowed      bool `yaml:"warn_install_allowed" json:"warn_install_allowed"`
	BlockOnUnknownRegistry  bool `yaml:"block_on_unknown_registry" json:"block_on_unknown_registry"`
	BlockMinScore           int  `yaml:"block_min_score" json:"block_min_score"`
	WarnMinScore            int  `yaml:"warn_min_score" json:"warn_min_score"`
}

type ScopedRule struct {
	ID    string          `yaml:"id" json:"id"`
	Match ScopedRuleMatch `yaml:"match" json:"match"`
	Apply ScopedRuleApply `yaml:"apply" json:"apply"`
}

type ScopesConfig struct {
	ScopedRules []ScopedRule `yaml:"scoped_rules" json:"scoped_rules"`
}
