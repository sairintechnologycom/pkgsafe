package mcp

import (
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/registry"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	scargo "github.com/sairintechnologycom/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/sairintechnologycom/pkgsafe/internal/scanner/golang"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ScanOpts carries optional per-call scanning parameters.
type ScanOpts struct {
	RequestedBy    string
	Environment    string
	SandboxEnabled bool
	BehaviorMode   types.BehaviorMode
	TimeoutSecs    int
	NetworkMode    string
	RegistryName   string
}

// scanPackage runs the appropriate ecosystem scanner and returns the raw result.
func (e *Executor) scanPackage(eco, name, version string, pol policy.Policy, offline bool, opts ScanOpts) (types.ScanResult, error) {
	eco = strings.ToLower(eco)

	env := opts.Environment
	if env == "" {
		if opts.RequestedBy == "ai_agent" {
			env = "ai_agent"
		} else {
			env = "developer"
		}
	}

	switch eco {
	case "pypi":
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || offline
		scanner.SandboxEnabled = opts.SandboxEnabled
		scanner.BehaviorMode = opts.BehaviorMode
		scanner.RequestedBy = opts.RequestedBy
		scanner.Environment = env
		scanner.RegistryName = opts.RegistryName
		return scanner.ScanPackage(name, version)

	case "cargo":
		scanner := scargo.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || offline
		scanner.RequestedBy = opts.RequestedBy
		scanner.Environment = env
		return scanner.ScanPackage(name, version)

	case "go", "golang":
		scanner := sgolang.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || offline
		scanner.RequestedBy = opts.RequestedBy
		scanner.Environment = env
		return scanner.ScanPackage(name, version)

	default: // npm (and any unknown ecosystem)
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || offline
		scanner.SandboxEnabled = opts.SandboxEnabled
		scanner.BehaviorMode = opts.BehaviorMode

		timeoutSecs := opts.TimeoutSecs
		if timeoutSecs == 0 {
			timeoutSecs = pol.Sandbox.DefaultTimeoutSeconds
		}
		if timeoutSecs == 0 {
			timeoutSecs = 10
		}
		scanner.SandboxTimeout = time.Duration(timeoutSecs) * time.Second

		netMode := opts.NetworkMode
		if netMode == "" {
			netMode = pol.Sandbox.NetworkMode
		}
		if netMode == "" {
			netMode = "disabled"
		}
		scanner.NetworkMode = netMode
		scanner.RequestedBy = opts.RequestedBy
		scanner.Environment = env
		scanner.RegistryName = opts.RegistryName
		return scanner.ScanPackage(name, version)
	}
}

// evaluatePackage runs a full scan + enterprise control pass and returns:
//   - the enriched ScanResult,
//   - whether installation is allowed,
//   - any error.
func (e *Executor) evaluatePackage(eco, name, version string, pol policy.Policy, offline bool, requestedBy string, opts ScanOpts) (types.ScanResult, bool, error) {
	res, err := e.scanPackage(eco, name, version, pol, offline, opts)
	if err != nil {
		return res, false, err
	}

	// Resolve registry configuration
	var regName string
	var regCfg policy.RegistryConfig
	if opts.RegistryName != "" {
		if cfg, ok := pol.Registries.Registries[eco][opts.RegistryName]; ok {
			regName = opts.RegistryName
			regCfg = cfg
		}
	} else {
		regName, regCfg = registry.ResolveRegistry(eco, name, pol)
	}

	env := opts.Environment
	if env == "" {
		if requestedBy == "ai_agent" {
			env = "ai_agent"
		} else {
			env = "developer"
		}
	}

	// Apply ai_agent suspicious-package risk amplifier when applicable
	if requestedBy == "ai_agent" && len(res.Reasons) > 0 {
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
				res = risk.ApplyEnterpriseControls(res, pol, regName, regCfg, requestedBy, env)
			}
		}
	}

	// Determine install permission
	installAllowed := true
	if res.Decision == types.DecisionBlock {
		installAllowed = false
	} else if res.Decision == types.DecisionWarn {
		switch pol.Mode {
		case policy.ModeAudit:
			installAllowed = true
		case policy.ModeBlock:
			installAllowed = false
		default:
			if requestedBy == "ai_agent" {
				installAllowed = pol.MCP.AIAgentDefaultInstallAllowedOnWarn
			} else {
				installAllowed = pol.MCP.HumanDefaultInstallAllowedOnWarn
			}
		}
	}

	// Critical sandbox finding always blocks AI agent installs
	if requestedBy == "ai_agent" && res.Sandbox.Enabled && res.Sandbox.Available {
		for _, script := range res.Sandbox.ScriptsExecuted {
			for _, f := range script.Findings {
				if f.Severity == "critical" {
					installAllowed = false
					break
				}
			}
		}
	}

	return res, installAllowed, nil
}
