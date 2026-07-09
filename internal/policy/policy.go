package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeWarn  Mode = "warn"
	ModeBlock Mode = "block"
	ModeAudit Mode = "audit"
)

type Rule struct {
	Enabled           bool
	Severity          string
	Score             int
	MaxAgeDays        int
	BlockInStrictMode bool
}

type PackageLists struct {
	NPM  []string
	PyPI []string
}

type MCPSettings struct {
	Enabled                            bool
	DefaultMode                        string
	AIAgentDefaultInstallAllowedOnWarn bool
	HumanDefaultInstallAllowedOnWarn   bool
}

type SandboxSettings struct {
	Enabled                 bool
	BehaviorMode            string
	DefaultTimeoutSeconds   int
	NetworkMode             string
	KeepSandbox             bool
	FailOpenWhenUnavailable bool
}

type EcosystemSettings struct {
	NPM  EcosystemSetting
	PyPI EcosystemSetting
}

type EcosystemSetting struct {
	Enabled bool
}

type CISettings struct {
	FailOn      string
	ChangedOnly bool
	CommentPR   bool
	UploadSARIF bool
}

type InstallInterceptionSettings struct {
	Enabled                           bool
	DefaultMode                       string
	ConfirmOnWarn                     bool
	AllowYesOnWarn                    bool
	AllowForceRiskAccept              bool
	ForceRiskAcceptRequiresReason     bool
	BlockKnownMalwareAlways           bool
	BlockCredentialAccessAlways       bool
	AIAgentWarnRequiresConfirmation   bool
	NonInteractiveWarnBlocksByDefault bool
	AuditLogEnabled                   bool
	AuditLogPath                      string
}

type PackageManagerSetting struct {
	Enabled              bool
	RealBinary           string
	ScanProjectInstall   bool
	ScanCIInstall        bool
	ScanRequirementsFile bool
}

type PackageManagersSettings struct {
	NPM       PackageManagerSetting
	Pip       PackageManagerSetting
	PythonPip PackageManagerSetting
}

type AgentPolicy struct {
	Mode                             string `yaml:"mode"`
	WarnRequiresHuman                bool   `yaml:"warn_requires_human"`
	BlockInstallCommands             bool   `yaml:"block_install_commands"`
	AllowAgentExceptions             bool   `yaml:"allow_agent_exceptions"`
	RequirePkgSafeCheckBeforeInstall bool   `yaml:"require_pkg_safe_check_before_install"`
}

type Policy struct {
	SchemaVersion       string
	Mode                Mode
	Ecosystems          EcosystemSettings
	Thresholds          types.Thresholds
	ProtectedPaths      []string
	TrustedPackages     PackageLists
	BlockedPackages     PackageLists
	Rules               map[string]Rule
	BlockPatterns       []string
	WarnPatterns        []string
	MCP                 MCPSettings
	Sandbox             SandboxSettings
	CI                  CISettings
	InstallInterception InstallInterceptionSettings
	PackageManagers     PackageManagersSettings
	AgentPolicy         AgentPolicy

	// Enterprise fields
	PolicyPackName      string
	PolicyPackVersion   string
	PolicyPackOwner     string
	PolicyPackSource    string
	Registries          RegistriesConfig
	TrustedPackageRules []TrustedPackageRule
	BlockedPackageRules []BlockedPackageRule
	Exceptions          []Exception
	ScopedRules         []ScopedRule
}

func Default() Policy {
	return Policy{
		SchemaVersion: "1.0",
		Mode:          ModeWarn,
		Ecosystems: EcosystemSettings{
			NPM:  EcosystemSetting{Enabled: true},
			PyPI: EcosystemSetting{Enabled: true},
		},
		Thresholds: types.Thresholds{
			AllowMaxScore: 29,
			WarnMaxScore:  69,
			BlockMinScore: 70,
		},
		AgentPolicy: AgentPolicy{
			Mode:                             "warn",
			WarnRequiresHuman:                true,
			BlockInstallCommands:             true,
			AllowAgentExceptions:             false,
			RequirePkgSafeCheckBeforeInstall: false,
		},
		ProtectedPaths: []string{
			"~/.aws", "~/.azure", "~/.gcp", "~/.ssh", "~/.kube",
			"~/.npmrc", "~/.pypirc", ".env", ".env.local", ".vault-token",
		},
		TrustedPackages: PackageLists{
			NPM:  []string{"lodash", "axios", "react", "express", "typescript"},
			PyPI: []string{"requests", "flask", "django", "fastapi", "numpy", "pandas", "pydantic", "pytest"},
		},
		BlockedPackages: PackageLists{NPM: []string{}, PyPI: []string{}},
		Rules: map[string]Rule{
			"lifecycle_script_present":            {Enabled: true, Severity: "medium", Score: 20},
			"undeclared_source_import":            {Enabled: true, Severity: "medium", Score: 15},
			"direct_use_of_transitive_dependency": {Enabled: true, Severity: "medium", Score: 15},
			"package_json_lockfile_mismatch":      {Enabled: true, Severity: "low", Score: 10},
			"unresolved_dynamic_import":           {Enabled: true, Severity: "high", Score: 30},
			"network_command_in_lifecycle":        {Enabled: true, Severity: "high", Score: 30, BlockInStrictMode: true},
			"credential_path_reference":           {Enabled: true, Severity: "critical", Score: 100},
			"secret_keyword_reference":            {Enabled: true, Severity: "high", Score: 35},
			"obfuscated_script":                   {Enabled: true, Severity: "high", Score: 25},
			"typosquat_candidate":                 {Enabled: true, Severity: "high", Score: 25},
			"missing_repository":                  {Enabled: true, Severity: "low", Score: 10},
			"missing_license":                     {Enabled: true, Severity: "low", Score: 5},
			"new_package":                         {Enabled: true, Severity: "medium", Score: 15, MaxAgeDays: 14},
			"trusted_package_reduction":           {Enabled: true, Severity: "informational", Score: -20},
			"blocked_package":                     {Enabled: true, Severity: "critical", Score: 100},
			"known_vulnerability_critical":        {Enabled: true, Severity: "critical", Score: 70},
			"known_vulnerability_high":            {Enabled: true, Severity: "high", Score: 50},
			"known_vulnerability_medium":          {Enabled: true, Severity: "medium", Score: 25},
			"known_vulnerability_low":             {Enabled: true, Severity: "low", Score: 10},
			// Fail-closed marker: emitted when the OSV advisory lookup could not
			// complete, so the package was NOT checked for known vulnerabilities.
			// Scores into the warn band on its own and blocks in strict/block
			// mode. Disable this rule to opt back into fail-open behavior.
			"vulnerability_data_unavailable":         {Enabled: true, Severity: "high", Score: 50, BlockInStrictMode: true},
			"known_malware_indicator":                {Enabled: true, Severity: "critical", Score: 100},
			"ai_package_squatting_candidate":         {Enabled: true, Severity: "high", Score: 25},
			"ai_agent_requested_suspicious_package":  {Enabled: true, Severity: "high", Score: 15},
			"credential_canary_read":                 {Enabled: true, Severity: "critical", Score: 100},
			"credential_canary_exfiltration_attempt": {Enabled: true, Severity: "critical", Score: 100},
			"cloud_metadata_access":                  {Enabled: true, Severity: "critical", Score: 100},
			"npm_token_access":                       {Enabled: true, Severity: "critical", Score: 100},
			"ssh_key_access":                         {Enabled: true, Severity: "critical", Score: 100},
			"env_secret_access":                      {Enabled: true, Severity: "critical", Score: 100},
			"network_call_from_lifecycle":            {Enabled: true, Severity: "high", Score: 40},
			"shell_download_execute":                 {Enabled: true, Severity: "critical", Score: 100},
			"encoded_payload_execution":              {Enabled: true, Severity: "high", Score: 40},
			"unexpected_binary_write":                {Enabled: true, Severity: "high", Score: 30},
			"child_process_spawn":                    {Enabled: true, Severity: "medium", Score: 20},
			"home_directory_enumeration":             {Enabled: true, Severity: "medium", Score: 20},
			"environment_variable_enumeration":       {Enabled: true, Severity: "medium", Score: 20},
			"pypi_source_distribution_only":          {Enabled: true, Severity: "medium", Score: 15},
			"pypi_yanked_release":                    {Enabled: true, Severity: "high", Score: 40},
			"pypi_setup_py_present":                  {Enabled: true, Severity: "medium", Score: 15},
			"pypi_setup_py_shell_execution":          {Enabled: true, Severity: "high", Score: 50},
			"pypi_setup_py_network_call":             {Enabled: true, Severity: "critical", Score: 100},
			"pypi_setup_py_credential_access":        {Enabled: true, Severity: "critical", Score: 100},
			"pypi_unknown_build_backend":             {Enabled: true, Severity: "medium", Score: 20},
			"pypi_in_tree_build_backend":             {Enabled: true, Severity: "high", Score: 45},
			"pypi_build_requires_direct_reference":   {Enabled: true, Severity: "high", Score: 60},
			"pypi_compiled_bytecode_payload":         {Enabled: true, Severity: "high", Score: 40},
			"pypi_wheel_record_missing":              {Enabled: true, Severity: "medium", Score: 25},
			"pypi_wheel_record_unlisted_files":       {Enabled: true, Severity: "high", Score: 35},
			"pypi_eval_exec_usage":                   {Enabled: true, Severity: "high", Score: 45},
			"pypi_base64_exec_payload":               {Enabled: true, Severity: "critical", Score: 100},
			"pypi_network_call":                      {Enabled: true, Severity: "high", Score: 40},
			"pypi_credential_path_access":            {Enabled: true, Severity: "critical", Score: 100},
			"pypi_env_secret_access":                 {Enabled: true, Severity: "high", Score: 40},
			"pypi_cloud_metadata_access":             {Enabled: true, Severity: "critical", Score: 100},
			"pypi_native_extension":                  {Enabled: true, Severity: "medium", Score: 20},
			"pypi_ai_package_squatting_candidate":    {Enabled: true, Severity: "high", Score: 25},
			"dependency_confusion_candidate":         {Enabled: true, Severity: "critical", Score: 100},
			"private_scope_public_registry":          {Enabled: true, Severity: "critical", Score: 100},
			"http_registry_warning":                  {Enabled: true, Severity: "high", Score: 40},
			"unapproved_registry_url":                {Enabled: true, Severity: "critical", Score: 100},
		},
		BlockPatterns: []string{
			"~/.aws", "~/.azure", "~/.gcp", "~/.ssh", "~/.kube", "~/.npmrc", "~/.pypirc",
			".aws", ".azure", ".gcp", ".ssh", ".kube", ".npmrc", ".pypirc",
			".env", ".env.local", ".vault-token", "id_rsa", "credentials",
		},
		WarnPatterns: []string{
			"curl", "wget", "invoke-webrequest", "http://", "https://", "bash -c", "sh -c",
			"base64", "eval", "child_process", "powershell", "netcat", " nc ",
			"aws_access_key_id", "aws_secret_access_key", "github_token", "vault_token", "token", "secret",
		},
		MCP: MCPSettings{
			Enabled:                            true,
			DefaultMode:                        "warn",
			AIAgentDefaultInstallAllowedOnWarn: false,
			HumanDefaultInstallAllowedOnWarn:   true,
		},
		Sandbox: SandboxSettings{
			Enabled:                 false,
			BehaviorMode:            string(types.BehaviorDisabled),
			DefaultTimeoutSeconds:   10,
			NetworkMode:             "disabled",
			KeepSandbox:             false,
			FailOpenWhenUnavailable: true,
		},
		CI: CISettings{
			FailOn:      "block",
			ChangedOnly: true,
			CommentPR:   true,
			UploadSARIF: true,
		},
		InstallInterception: InstallInterceptionSettings{
			Enabled:                           true,
			DefaultMode:                       "warn",
			ConfirmOnWarn:                     true,
			AllowYesOnWarn:                    true,
			AllowForceRiskAccept:              true,
			ForceRiskAcceptRequiresReason:     true,
			BlockKnownMalwareAlways:           true,
			BlockCredentialAccessAlways:       true,
			AIAgentWarnRequiresConfirmation:   true,
			NonInteractiveWarnBlocksByDefault: true,
			AuditLogEnabled:                   true,
			AuditLogPath:                      "~/.pkgsafe/audit.log",
		},
		PackageManagers: PackageManagersSettings{
			NPM: PackageManagerSetting{
				Enabled:            true,
				ScanProjectInstall: true,
				ScanCIInstall:      true,
			},
			Pip: PackageManagerSetting{
				Enabled:              true,
				ScanRequirementsFile: true,
			},
			PythonPip: PackageManagerSetting{
				Enabled: true,
			},
		},
	}
}

func Load(path string) (Policy, error) {
	if strings.TrimSpace(path) == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("load policy %q: %w", path, err)
	}
	pol := Default()
	if err := parseYAMLPolicy(string(b), &pol); err != nil {
		return Policy{}, fmt.Errorf("parse policy %q: %w", path, err)
	}

	// Unmarshal enterprise fields using gopkg.in/yaml.v3
	var ent struct {
		Registries          map[string]map[string]RegistryConfig `yaml:"registries"`
		TrustedPackageRules []TrustedPackageRule                 `yaml:"trusted_package_rules"`
		BlockedPackageRules []BlockedPackageRule                 `yaml:"blocked_package_rules"`
		Exceptions          []Exception                          `yaml:"exceptions"`
		ScopedRules         []ScopedRule                         `yaml:"scoped_rules"`
		AgentPolicy         AgentPolicy                          `yaml:"agent_policy"`
	}
	ent.AgentPolicy = pol.AgentPolicy
	if err := yaml.Unmarshal(b, &ent); err == nil {
		if len(ent.Registries) > 0 {
			pol.Registries.Registries = ent.Registries
		}
		if len(ent.TrustedPackageRules) > 0 {
			pol.TrustedPackageRules = ent.TrustedPackageRules
		}
		if len(ent.BlockedPackageRules) > 0 {
			pol.BlockedPackageRules = ent.BlockedPackageRules
		}
		if len(ent.Exceptions) > 0 {
			pol.Exceptions = ent.Exceptions
		}
		if len(ent.ScopedRules) > 0 {
			pol.ScopedRules = ent.ScopedRules
		}
		pol.AgentPolicy = ent.AgentPolicy
	}

	if err := Validate(pol); err != nil {
		return Policy{}, fmt.Errorf("invalid policy %q: %w", path, err)
	}
	return pol, nil
}

func Validate(pol Policy) error {
	if pol.SchemaVersion != "" && pol.SchemaVersion != "1.0" {
		return fmt.Errorf("unsupported schema_version %q", pol.SchemaVersion)
	}
	if pol.Mode != ModeAudit && pol.Mode != ModeWarn && pol.Mode != ModeBlock {
		return fmt.Errorf("mode must be one of audit, warn, block")
	}
	if pol.CI.FailOn != "" && pol.CI.FailOn != "none" && pol.CI.FailOn != "warn" && pol.CI.FailOn != "block" {
		return fmt.Errorf("ci.fail_on must be one of none, warn, block")
	}
	if pol.InstallInterception.AllowForceRiskAccept && !pol.InstallInterception.ForceRiskAcceptRequiresReason {
		return fmt.Errorf("force risk accept must require a reason")
	}
	t := pol.Thresholds
	if t.AllowMaxScore < 0 || t.WarnMaxScore < 0 || t.BlockMinScore < 0 ||
		t.AllowMaxScore > 100 || t.WarnMaxScore > 100 || t.BlockMinScore > 100 {
		return fmt.Errorf("thresholds must be between 0 and 100")
	}
	if !(t.AllowMaxScore < t.WarnMaxScore && t.WarnMaxScore < t.BlockMinScore) {
		return fmt.Errorf("thresholds must satisfy allow_max_score < warn_max_score < block_min_score")
	}
	defaultPol := Default()
	for id, rule := range pol.Rules {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("rule id cannot be empty")
		}
		if strings.TrimSpace(rule.Severity) == "" {
			return fmt.Errorf("rule %s severity is required", id)
		}
		if _, exists := defaultPol.Rules[id]; !exists {
			return fmt.Errorf("unknown rule ID: %s", id)
		}
		if rule.Severity != "low" && rule.Severity != "medium" && rule.Severity != "high" && rule.Severity != "critical" && rule.Severity != "informational" {
			return fmt.Errorf("invalid severity for rule %s: %s", id, rule.Severity)
		}
		if rule.Score < -100 || rule.Score > 100 {
			return fmt.Errorf("invalid score for rule %s: %d", id, rule.Score)
		}
	}

	// 1. Conflicting trust/block rules
	trustedMap := make(map[string]bool)
	blockedMap := make(map[string]bool)
	for _, rule := range pol.TrustedPackageRules {
		key := rule.Name + ":" + rule.VersionRange
		trustedMap[key] = true
	}
	for _, rule := range pol.BlockedPackageRules {
		key := rule.Name + ":" + rule.VersionRange
		blockedMap[key] = true
	}
	for key := range trustedMap {
		if blockedMap[key] {
			return fmt.Errorf("conflicting entry found in both trusted and blocked lists: %s", key)
		}
	}

	// 2. Expired exceptions
	for _, exc := range pol.Exceptions {
		if exc.IsExpired() {
			return fmt.Errorf("exception %s is expired", exc.ID)
		}
		if strings.TrimSpace(exc.ID) == "" {
			return fmt.Errorf("exception id is required")
		}
		if strings.TrimSpace(exc.Package) == "" {
			return fmt.Errorf("exception %s package is required", exc.ID)
		}
		if strings.TrimSpace(exc.Reason) == "" {
			return fmt.Errorf("exception %s reason is required", exc.ID)
		}
		if strings.TrimSpace(exc.ApprovedBy) == "" {
			return fmt.Errorf("exception %s approved_by is required", exc.ID)
		}
	}
	if err := validateHardBlockInvariants(pol); err != nil {
		return err
	}

	// 3. Invalid wildcard patterns
	for _, rule := range pol.ScopedRules {
		if rule.Match.Package != "" {
			if strings.Contains(rule.Match.Package, "*") && !strings.HasSuffix(rule.Match.Package, "*") {
				return fmt.Errorf("invalid wildcard scope in match: %s", rule.Match.Package)
			}
		}
	}

	return nil
}

func validateHardBlockInvariants(pol Policy) error {
	hardBlockRules := []string{
		"blocked_package",
		"known_malware_indicator",
		"credential_path_reference",
		"credential_canary_read",
		"credential_canary_exfiltration_attempt",
		"cloud_metadata_access",
		"npm_token_access",
		"ssh_key_access",
		"env_secret_access",
		"shell_download_execute",
		"pypi_setup_py_network_call",
		"pypi_setup_py_credential_access",
		"dependency_confusion_candidate",
		"private_scope_public_registry",
		"unapproved_registry_url",
	}
	for _, id := range hardBlockRules {
		rule, ok := pol.Rules[id]
		if !ok {
			return fmt.Errorf("hard-block rule %s is missing", id)
		}
		if !rule.Enabled {
			return fmt.Errorf("hard-block rule %s cannot be disabled", id)
		}
		if rule.Severity != "critical" {
			return fmt.Errorf("hard-block rule %s must remain critical", id)
		}
		if rule.Score < pol.Thresholds.BlockMinScore {
			return fmt.Errorf("hard-block rule %s score must be >= block_min_score", id)
		}
	}
	if !pol.InstallInterception.BlockKnownMalwareAlways {
		return fmt.Errorf("block_known_malware_always must remain true")
	}
	if !pol.InstallInterception.BlockCredentialAccessAlways {
		return fmt.Errorf("block_credential_access_always must remain true")
	}
	return nil
}

func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block":
		return ModeBlock
	case "audit":
		return ModeAudit
	case "warn", "":
		return ModeWarn
	default:
		return Mode(strings.ToLower(strings.TrimSpace(s)))
	}
}

func ApplyMode(pol Policy, mode string) (Policy, error) {
	if strings.TrimSpace(mode) == "" {
		return pol, nil
	}
	parsed := ParseMode(mode)
	if parsed != ModeAudit && parsed != ModeWarn && parsed != ModeBlock {
		return Policy{}, fmt.Errorf("mode must be one of audit, warn, block")
	}
	pol.Mode = parsed
	return pol, nil
}

func IsTrusted(pol Policy, ecosystem, name string) bool {
	return containsPackage(listForEcosystem(pol.TrustedPackages, ecosystem), name)
}

func IsBlocked(pol Policy, ecosystem, name string) bool {
	return containsPackage(listForEcosystem(pol.BlockedPackages, ecosystem), name)
}

func RuleFor(pol Policy, id string) (Rule, bool) {
	rule, ok := pol.Rules[id]
	return rule, ok && rule.Enabled
}

func listForEcosystem(l PackageLists, ecosystem string) []string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return l.NPM
	case "pypi":
		return l.PyPI
	}
	return nil
}

func containsPackage(packages []string, name string) bool {
	for _, pkg := range packages {
		if strings.EqualFold(strings.TrimSpace(pkg), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func parseYAMLPolicy(raw string, pol *Policy) error {
	var section, subsection, ruleID string
	var hasProtectedPaths bool
	for lineNo, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimRight(rawLine, " \t\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "- ") {
			item := unquote(strings.TrimSpace(strings.TrimPrefix(text, "- ")))
			switch {
			case section == "protected_paths":
				pol.ProtectedPaths = append(pol.ProtectedPaths, item)
			case section == "trusted_packages" && subsection == "npm":
				pol.TrustedPackages.NPM = append(pol.TrustedPackages.NPM, item)
			case section == "trusted_packages" && subsection == "pypi":
				pol.TrustedPackages.PyPI = append(pol.TrustedPackages.PyPI, item)
			case section == "blocked_packages" && subsection == "npm":
				pol.BlockedPackages.NPM = append(pol.BlockedPackages.NPM, item)
			case section == "blocked_packages" && subsection == "pypi":
				pol.BlockedPackages.PyPI = append(pol.BlockedPackages.PyPI, item)
			case section == "registries" || section == "scoped_rules" || section == "exceptions" || section == "trusted_package_rules" || section == "blocked_package_rules":
				// Skip list items for these sections in custom parser
			default:
				return fmt.Errorf("line %d: list item is not under a supported list", lineNo+1)
			}
			continue
		}
		key, val, ok := strings.Cut(text, ":")
		if !ok {
			return fmt.Errorf("line %d: expected key: value", lineNo+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if indent == 0 {
			section, subsection, ruleID = key, "", ""
			switch key {
			case "schema_version":
				pol.SchemaVersion = unquote(val)
			case "mode":
				pol.Mode = ParseMode(unquote(val))
			case "thresholds", "rules", "mcp", "sandbox", "ci", "ecosystems", "install_interception", "package_managers", "registries", "scoped_rules", "exceptions", "trusted_package_rules", "blocked_package_rules", "agent_policy":
			case "protected_paths":
				pol.ProtectedPaths = nil
				pol.BlockPatterns = nil
				hasProtectedPaths = true
			case "trusted_packages":
				pol.TrustedPackages = PackageLists{}
			case "blocked_packages":
				pol.BlockedPackages = PackageLists{}
			default:
				return fmt.Errorf("line %d: unsupported top-level key %q", lineNo+1, key)
			}
			continue
		}
		switch section {
		case "ecosystems":
			if indent == 2 && val == "" {
				subsection = key
				continue
			}
			if indent != 4 || subsection == "" {
				return fmt.Errorf("line %d: expected ecosystem property", lineNo+1)
			}
			if key != "enabled" {
				return fmt.Errorf("line %d: unsupported ecosystem property %q", lineNo+1, key)
			}
			enabled := strings.EqualFold(unquote(val), "true")
			switch subsection {
			case "npm":
				pol.Ecosystems.NPM.Enabled = enabled
			case "pypi":
				pol.Ecosystems.PyPI.Enabled = enabled
			default:
				return fmt.Errorf("line %d: unsupported ecosystem %q", lineNo+1, subsection)
			}
		case "ci":
			if indent != 2 {
				return fmt.Errorf("line %d: expected ci property", lineNo+1)
			}
			switch key {
			case "fail_on":
				pol.CI.FailOn = unquote(val)
			case "changed_only":
				pol.CI.ChangedOnly = strings.EqualFold(unquote(val), "true")
			case "comment_pr":
				pol.CI.CommentPR = strings.EqualFold(unquote(val), "true")
			case "upload_sarif":
				pol.CI.UploadSARIF = strings.EqualFold(unquote(val), "true")
			default:
				return fmt.Errorf("line %d: unsupported ci property %q", lineNo+1, key)
			}
		case "sandbox":
			if indent != 2 {
				return fmt.Errorf("line %d: expected sandbox property", lineNo+1)
			}
			switch key {
			case "enabled":
				pol.Sandbox.Enabled = strings.EqualFold(unquote(val), "true")
			case "behavior", "behavior_mode":
				mode := unquote(val)
				switch types.BehaviorMode(mode) {
				case types.BehaviorDisabled, types.BehaviorHeuristic, types.BehaviorIsolated:
					pol.Sandbox.BehaviorMode = mode
				default:
					return fmt.Errorf("line %d: behavior_mode must be disabled, heuristic, or isolated", lineNo+1)
				}
			case "default_timeout_seconds":
				n, err := strconv.Atoi(unquote(val))
				if err != nil {
					return fmt.Errorf("line %d: default_timeout_seconds must be an integer", lineNo+1)
				}
				pol.Sandbox.DefaultTimeoutSeconds = n
			case "network_mode":
				pol.Sandbox.NetworkMode = unquote(val)
			case "keep_sandbox":
				pol.Sandbox.KeepSandbox = strings.EqualFold(unquote(val), "true")
			case "fail_open_when_unavailable":
				pol.Sandbox.FailOpenWhenUnavailable = strings.EqualFold(unquote(val), "true")
			default:
				return fmt.Errorf("line %d: unsupported sandbox property %q", lineNo+1, key)
			}
		case "mcp":
			if indent != 2 {
				return fmt.Errorf("line %d: expected mcp property", lineNo+1)
			}
			switch key {
			case "enabled":
				pol.MCP.Enabled = strings.EqualFold(unquote(val), "true")
			case "default_mode":
				pol.MCP.DefaultMode = unquote(val)
			case "ai_agent_default_install_allowed_on_warn":
				pol.MCP.AIAgentDefaultInstallAllowedOnWarn = strings.EqualFold(unquote(val), "true")
			case "human_default_install_allowed_on_warn":
				pol.MCP.HumanDefaultInstallAllowedOnWarn = strings.EqualFold(unquote(val), "true")
			default:
				return fmt.Errorf("line %d: unsupported mcp property %q", lineNo+1, key)
			}
		case "thresholds":
			n, err := strconv.Atoi(unquote(val))
			if err != nil {
				return fmt.Errorf("line %d: threshold %s must be an integer", lineNo+1, key)
			}
			switch key {
			case "allow_max_score":
				pol.Thresholds.AllowMaxScore = n
			case "warn_max_score":
				pol.Thresholds.WarnMaxScore = n
			case "block_min_score":
				pol.Thresholds.BlockMinScore = n
			default:
				return fmt.Errorf("line %d: unsupported threshold %q", lineNo+1, key)
			}
		case "trusted_packages", "blocked_packages":
			if indent == 2 && val == "" {
				subsection = key
			} else if indent == 2 && val == "[]" {
				subsection = key
			} else {
				return fmt.Errorf("line %d: expected ecosystem list", lineNo+1)
			}
		case "rules":
			if indent == 2 && val == "" {
				ruleID = key
				if pol.Rules == nil {
					pol.Rules = map[string]Rule{}
				}
				if _, ok := pol.Rules[ruleID]; !ok {
					pol.Rules[ruleID] = Rule{}
				}
				continue
			}
			if indent != 4 || ruleID == "" {
				return fmt.Errorf("line %d: expected rule property", lineNo+1)
			}
			rule := pol.Rules[ruleID]
			switch key {
			case "enabled":
				rule.Enabled = strings.EqualFold(unquote(val), "true")
			case "severity":
				rule.Severity = unquote(val)
			case "score":
				n, err := strconv.Atoi(unquote(val))
				if err != nil {
					return fmt.Errorf("line %d: score must be an integer", lineNo+1)
				}
				rule.Score = n
			case "max_age_days":
				n, err := strconv.Atoi(unquote(val))
				if err != nil {
					return fmt.Errorf("line %d: max_age_days must be an integer", lineNo+1)
				}
				rule.MaxAgeDays = n
			case "block_in_strict_mode":
				rule.BlockInStrictMode = strings.EqualFold(unquote(val), "true")
			default:
				return fmt.Errorf("line %d: unsupported rule property %q", lineNo+1, key)
			}
			pol.Rules[ruleID] = rule
		case "install_interception":
			if indent != 2 {
				return fmt.Errorf("line %d: expected install_interception property", lineNo+1)
			}
			switch key {
			case "enabled":
				pol.InstallInterception.Enabled = strings.EqualFold(unquote(val), "true")
			case "default_mode":
				pol.InstallInterception.DefaultMode = unquote(val)
			case "confirm_on_warn":
				pol.InstallInterception.ConfirmOnWarn = strings.EqualFold(unquote(val), "true")
			case "allow_yes_on_warn":
				pol.InstallInterception.AllowYesOnWarn = strings.EqualFold(unquote(val), "true")
			case "allow_force_risk_accept":
				pol.InstallInterception.AllowForceRiskAccept = strings.EqualFold(unquote(val), "true")
			case "force_risk_accept_requires_reason":
				pol.InstallInterception.ForceRiskAcceptRequiresReason = strings.EqualFold(unquote(val), "true")
			case "block_known_malware_always":
				pol.InstallInterception.BlockKnownMalwareAlways = strings.EqualFold(unquote(val), "true")
			case "block_credential_access_always":
				pol.InstallInterception.BlockCredentialAccessAlways = strings.EqualFold(unquote(val), "true")
			case "ai_agent_warn_requires_confirmation":
				pol.InstallInterception.AIAgentWarnRequiresConfirmation = strings.EqualFold(unquote(val), "true")
			case "non_interactive_warn_blocks_by_default":
				pol.InstallInterception.NonInteractiveWarnBlocksByDefault = strings.EqualFold(unquote(val), "true")
			case "audit_log_enabled":
				pol.InstallInterception.AuditLogEnabled = strings.EqualFold(unquote(val), "true")
			case "audit_log_path":
				pol.InstallInterception.AuditLogPath = unquote(val)
			default:
				return fmt.Errorf("line %d: unsupported install_interception property %q", lineNo+1, key)
			}
		case "package_managers":
			if indent == 2 && val == "" {
				subsection = key
				continue
			}
			if indent != 4 || subsection == "" {
				return fmt.Errorf("line %d: expected package_managers property", lineNo+1)
			}
			switch subsection {
			case "npm":
				switch key {
				case "enabled":
					pol.PackageManagers.NPM.Enabled = strings.EqualFold(unquote(val), "true")
				case "real_binary":
					pol.PackageManagers.NPM.RealBinary = unquote(val)
				case "scan_project_install":
					pol.PackageManagers.NPM.ScanProjectInstall = strings.EqualFold(unquote(val), "true")
				case "scan_ci_install":
					pol.PackageManagers.NPM.ScanCIInstall = strings.EqualFold(unquote(val), "true")
				default:
					return fmt.Errorf("line %d: unsupported npm property %q", lineNo+1, key)
				}
			case "pip":
				switch key {
				case "enabled":
					pol.PackageManagers.Pip.Enabled = strings.EqualFold(unquote(val), "true")
				case "real_binary":
					pol.PackageManagers.Pip.RealBinary = unquote(val)
				case "scan_requirements_file":
					pol.PackageManagers.Pip.ScanRequirementsFile = strings.EqualFold(unquote(val), "true")
				default:
					return fmt.Errorf("line %d: unsupported pip property %q", lineNo+1, key)
				}
			case "python_pip":
				switch key {
				case "enabled":
					pol.PackageManagers.PythonPip.Enabled = strings.EqualFold(unquote(val), "true")
				default:
					return fmt.Errorf("line %d: unsupported python_pip property %q", lineNo+1, key)
				}
			default:
				return fmt.Errorf("line %d: unsupported package manager %q", lineNo+1, subsection)
			}
		case "registries", "scoped_rules", "exceptions", "trusted_package_rules", "blocked_package_rules", "agent_policy":
			continue
		default:
			return fmt.Errorf("line %d: unsupported section %q", lineNo+1, section)
		}
	}
	if hasProtectedPaths {
		pol.BlockPatterns = deriveBlockPatterns(pol.ProtectedPaths)
	}
	return nil
}

func deriveBlockPatterns(paths []string) []string {
	seen := make(map[string]bool)
	var bp []string
	for _, path := range paths {
		if path == "" {
			continue
		}
		if !seen[path] {
			seen[path] = true
			bp = append(bp, path)
		}
		if strings.HasPrefix(path, "~/") {
			unprefixed := strings.TrimPrefix(path, "~/")
			if unprefixed != "" && !seen[unprefixed] {
				seen[unprefixed] = true
				bp = append(bp, unprefixed)
			}
		}
		if strings.Contains(path, ".ssh") {
			if !seen["id_rsa"] {
				seen["id_rsa"] = true
				bp = append(bp, "id_rsa")
			}
		}
		if strings.Contains(path, ".aws") {
			if !seen["credentials"] {
				seen["credentials"] = true
				bp = append(bp, "credentials")
			}
		}
	}
	return bp
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	return s
}
