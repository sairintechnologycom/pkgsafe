package mcp

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/agent"
	"github.com/niyam-ai/pkgsafe/internal/output"
	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	snpm "github.com/niyam-ai/pkgsafe/internal/scanner/npm"
	spypi "github.com/niyam-ai/pkgsafe/internal/scanner/pypi"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

// ValidatePackageInstallParams defines params for validating package installation.
type ValidatePackageInstallParams struct {
	Ecosystem             string `json:"ecosystem"`
	Name                  string `json:"name"`
	Version               string `json:"version"`
	RequestedBy           string `json:"requested_by"`
	ProjectPath           string `json:"project_path"`
	Mode                  string `json:"mode"`
	Offline               bool   `json:"offline"`
	Sandbox               bool   `json:"sandbox,omitempty"`
	SandboxTimeoutSeconds int    `json:"sandbox_timeout_seconds,omitempty"`
	NetworkMode           string `json:"network_mode,omitempty"`
	PolicyPack            string `json:"policy_pack"`
	Registry              string `json:"registry"`
}

type MCPSandboxResult struct {
	Enabled               bool `json:"enabled"`
	Available             bool `json:"available"`
	FindingsCount         int  `json:"findings_count"`
	CriticalFindingsCount int  `json:"critical_findings_count"`
}

// ValidatePackageInstallResult defines the structured tool response.
type ValidatePackageInstallResult struct {
	Ecosystem         string                     `json:"ecosystem"`
	Package           string                     `json:"package"`
	Version           string                     `json:"version"`
	RequestedBy       string                     `json:"requested_by"`
	Decision          string                     `json:"decision"`
	RiskScore         int                        `json:"risk_score"`
	InstallAllowed    bool                       `json:"install_allowed"`
	Mode              string                     `json:"mode"`
	Reasons           []types.Reason             `json:"reasons"`
	Vulnerabilities   []types.Vulnerability      `json:"vulnerabilities"`
	SafeAlternatives  []string                   `json:"safe_alternatives"`
	RecommendedAction string                     `json:"recommended_action"`
	Sandbox           *MCPSandboxResult          `json:"sandbox,omitempty"`
	Policy            *types.PolicyEvidence      `json:"policy,omitempty"`
	Registry          *types.RegistryEvidence    `json:"registry,omitempty"`
	Trust             *types.TrustEvidence       `json:"trust,omitempty"`
	Exception         *types.ExceptionEvidence   `json:"exception,omitempty"`
}

// ValidatePackageInstall evaluates if a package install should proceed.
func (e *Executor) ValidatePackageInstall(args json.RawMessage) CallToolResult {
	var p ValidatePackageInstallParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.Ecosystem == "" {
		p.Ecosystem = "npm"
	}
	if p.Ecosystem != "npm" && p.Ecosystem != "pypi" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("UNSUPPORTED_ECOSYSTEM", "Supported ecosystems are npm and pypi", map[string]string{"ecosystem": p.Ecosystem}),
			}},
			IsError: true,
		}
	}

	if p.Name == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("MISSING_PACKAGE_NAME", "Package name is required", nil),
			}},
			IsError: true,
		}
	}

	if p.Version == "" {
		p.Version = "latest"
	}

	if p.RequestedBy == "" {
		p.RequestedBy = "human"
	}

	repoPath := ""
	if p.ProjectPath != "" {
		repoPath = filepath.Join(p.ProjectPath, ".pkgsafe/policy.yaml")
	}
	pol, err := policy.ResolvePolicy(p.PolicyPack, repoPath, e.PolicyPath, p.Mode)
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	// Mode precedence: param mode > executor mode > policy default mode
	activeMode := pol.Mode
	if e.Mode != "" {
		activeMode = policy.ParseMode(e.Mode)
	}
	if p.Mode != "" {
		activeMode = policy.ParseMode(p.Mode)
	}
	pol.Mode = activeMode

	// Sandbox logic in MCP
	sandboxEnabled := p.Sandbox
	if !sandboxEnabled {
		sandboxEnabled = pol.Sandbox.Enabled
	}

	timeoutSecs := p.SandboxTimeoutSeconds
	if timeoutSecs == 0 {
		timeoutSecs = pol.Sandbox.DefaultTimeoutSeconds
	}
	if timeoutSecs == 0 {
		timeoutSecs = 10
	}

	netMode := p.NetworkMode
	if netMode == "" {
		netMode = pol.Sandbox.NetworkMode
	}
	if netMode == "" {
		netMode = "disabled"
	}

	env := "developer"
	if p.RequestedBy == "ai_agent" {
		env = "ai_agent"
	}

	var regName string
	var regCfg policy.RegistryConfig
	if p.Registry != "" {
		if cfg, ok := pol.Registries.Registries[p.Ecosystem][p.Registry]; ok {
			regName = p.Registry
			regCfg = cfg
		} else {
			regName = ""
			regCfg = policy.RegistryConfig{
				URL:     "",
				Type:    "unknown",
				Enabled: false,
			}
		}
	} else {
		regName, regCfg = registry.ResolveRegistry(p.Ecosystem, p.Name, pol)
	}

	var res types.ScanResult
	var scanErr error
	if p.Ecosystem == "pypi" {
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		scanner.SandboxEnabled = sandboxEnabled
		scanner.RequestedBy = p.RequestedBy
		scanner.Environment = env
		scanner.RegistryName = p.Registry
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	} else {
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		scanner.SandboxEnabled = sandboxEnabled
		scanner.SandboxTimeout = time.Duration(timeoutSecs) * time.Second
		scanner.NetworkMode = netMode
		scanner.RequestedBy = p.RequestedBy
		scanner.Environment = env
		scanner.RegistryName = p.Registry
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	}
	if scanErr != nil {
		te := MapScanError(scanErr, p.Ecosystem, p.Name, p.Version)
		b, _ := json.MarshalIndent(te, "", "  ")
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: string(b),
			}},
			IsError: true,
		}
	}

	hasCriticalSandboxFinding := false
	criticalSandboxFindingsCount := 0
	sandboxFindingsCount := 0
	if res.Sandbox.Enabled && res.Sandbox.Available {
		for _, script := range res.Sandbox.ScriptsExecuted {
			for _, f := range script.Findings {
				sandboxFindingsCount++
				if f.Severity == "critical" {
					hasCriticalSandboxFinding = true
					criticalSandboxFindingsCount++
				}
			}
		}
	}

	// Handle ai_agent requested risk increases
	if p.RequestedBy == "ai_agent" && len(res.Reasons) > 0 {
		hasRisks := false
		for _, r := range res.Reasons {
			if r.ID != "trusted_package_reduction" {
				hasRisks = true
				break
			}
		}
		if hasRisks {
			if _, ok := policy.RuleFor(pol, "ai_agent_requested_suspicious_package"); ok {
				findings := append(stripPolicyGenerated(res.Reasons), types.Reason{
					ID:          "ai_agent_requested_suspicious_package",
					Description: "AI agent requested suspicious package installation",
					Evidence:    res.Package.Name,
				})
				oldSandbox := res.Sandbox
				res = risk.Evaluate(res.Package, findings, res.Lifecycle, res.Suspicious, res.SafeAlternates, pol)
				res.Sandbox = oldSandbox
				res = risk.ApplyEnterpriseControls(res, pol, regName, regCfg, p.RequestedBy, env)
			}
		}
	}

	installAllowed := true
	if res.Decision == types.DecisionBlock {
		installAllowed = false
	} else if res.Decision == types.DecisionWarn {
		if pol.Mode == policy.ModeAudit {
			installAllowed = true
		} else if pol.Mode == policy.ModeBlock {
			installAllowed = false
		} else { // ModeWarn
			if p.RequestedBy == "ai_agent" {
				installAllowed = pol.MCP.AIAgentDefaultInstallAllowedOnWarn
			} else {
				installAllowed = pol.MCP.HumanDefaultInstallAllowedOnWarn
			}
		}
	}
	if p.RequestedBy == "ai_agent" && hasCriticalSandboxFinding {
		installAllowed = false
	}

	var safeAlts []string
	alts := agent.GetSafeAlternatives(p.Name)
	for _, alt := range alts {
		safeAlts = append(safeAlts, alt.Name)
	}

	recAction := output.RecommendedAction(res)
	if sandboxEnabled && !res.Sandbox.Available {
		recAction = "Sandbox requested but unavailable. Behavioral analysis was not performed. " + recAction
	}

	var mcpSandbox *MCPSandboxResult
	if sandboxEnabled {
		mcpSandbox = &MCPSandboxResult{
			Enabled:               res.Sandbox.Enabled,
			Available:             res.Sandbox.Available,
			FindingsCount:         sandboxFindingsCount,
			CriticalFindingsCount: criticalSandboxFindingsCount,
		}
	}

	toolRes := ValidatePackageInstallResult{
		Ecosystem:         res.Package.Ecosystem,
		Package:           res.Package.Name,
		Version:           res.Package.Version,
		RequestedBy:       p.RequestedBy,
		Decision:          string(res.Decision),
		RiskScore:         res.Score,
		InstallAllowed:    installAllowed,
		Mode:              string(pol.Mode),
		Reasons:           res.Reasons,
		Vulnerabilities:   res.Vulnerabilities,
		SafeAlternatives:  safeAlts,
		RecommendedAction: recAction,
		Sandbox:           mcpSandbox,
		Policy:            res.PolicyInfo,
		Registry:          res.RegistryInfo,
		Trust:             res.TrustInfo,
		Exception:         res.ExceptionInfo,
	}

	b, _ := json.MarshalIndent(toolRes, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(b),
		}},
		IsError: false,
	}
}

func serializeError(code, message string, details any) string {
	te := ToolError{}
	te.Error.Code = code
	te.Error.Message = message
	te.Error.Details = details
	b, _ := json.MarshalIndent(te, "", "  ")
	return string(b)
}

func stripPolicyGenerated(reasons []types.Reason) []types.Reason {
	var out []types.Reason
	for _, r := range reasons {
		switch r.ID {
		case "trusted_package_reduction", "blocked_package",
			"known_vulnerability_critical", "known_vulnerability_high",
			"known_vulnerability_medium", "known_vulnerability_low",
			"known_malware_indicator", "ai_agent_requested_suspicious_package":
			continue
		default:
			out = append(out, r)
		}
	}
	return out
}
