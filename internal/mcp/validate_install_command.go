package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ValidateInstallCommandParams defines input for validate_install_command.
type ValidateInstallCommandParams struct {
	Command     string `json:"command"`
	ProjectPath string `json:"project_path"`
	Mode        string `json:"mode"`
	Offline     bool   `json:"offline"`
	RequestedBy string `json:"requested_by"`
}

// ValidateInstallCommandPackage represents the status of a single package in the command.
type ValidateInstallCommandPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Decision  string `json:"decision"`
	RiskScore int    `json:"risk_score"`
}

// ValidateInstallCommandResult represents the output for validate_install_command.
type ValidateInstallCommandResult struct {
	Command           string                          `json:"command"`
	Ecosystem         string                          `json:"ecosystem"`
	Decision          string                          `json:"decision"`
	InstallAllowed    bool                            `json:"install_allowed"`
	Packages          []ValidateInstallCommandPackage `json:"packages"`
	RecommendedAction string                          `json:"recommended_action"`
	AgentInstruction  AgentInstruction                `json:"agent_instruction"`
}

// ValidateInstallCommand extracts and scans packages in an install command string.
func (e *Executor) ValidateInstallCommand(args json.RawMessage) CallToolResult {
	var p ValidateInstallCommandParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}
	if p.RequestedBy == "" {
		p.RequestedBy = "ai_agent"
	}

	parsedPkgs, err := agent.ParseInstallCommand(p.Command)
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_INSTALL_COMMAND", "Failed to parse command: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	pol, err := policy.Load(e.PolicyPath)
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if e.Mode != "" {
		pol.Mode = policy.ParseMode(e.Mode)
	}
	if p.Mode != "" {
		pol.Mode = policy.ParseMode(p.Mode)
	}

	npmScanner := snpm.New()
	npmScanner.Policy = pol
	npmScanner.Offline = e.Offline || p.Offline
	pypiScanner := spypi.New()
	pypiScanner.Policy = pol
	pypiScanner.Offline = e.Offline || p.Offline

	var packages []ValidateInstallCommandPackage
	hasBlock := false
	hasWarn := false
	ecosystem := "npm"

	for _, pp := range parsedPkgs {
		if pp.Ecosystem != "" {
			ecosystem = pp.Ecosystem
		}
		var res types.ScanResult
		var err error
		if ecosystem == "pypi" {
			res, err = pypiScanner.ScanPackage(pp.Name, pp.Version)
		} else {
			res, err = npmScanner.ScanPackage(pp.Name, pp.Version)
		}
		if err != nil {
			te := MapScanError(err, ecosystem, pp.Name, pp.Version)
			bErr, _ := json.MarshalIndent(te, "", "  ")
			return CallToolResult{
				Content: []ToolContent{{
					Type: "text",
					Text: string(bErr),
				}},
				IsError: true,
			}
		}

		if res.Decision == types.DecisionBlock {
			hasBlock = true
		} else if res.Decision == types.DecisionWarn {
			hasWarn = true
		}

		packages = append(packages, ValidateInstallCommandPackage{
			Name:      res.Package.Name,
			Version:   res.Package.Version,
			Decision:  string(res.Decision),
			RiskScore: res.Score,
		})
	}

	overallDecision := "allow"
	if hasBlock {
		overallDecision = "block"
	} else if hasWarn {
		overallDecision = "warn"
	}

	installAllowed := true
	if overallDecision == "block" {
		installAllowed = false
	} else if overallDecision == "warn" {
		if pol.Mode == policy.ModeAudit {
			installAllowed = true
		} else if pol.Mode == policy.ModeBlock {
			installAllowed = false
		} else { // ModeWarn
			// Default to AI agent settings for validation command
			if p.RequestedBy == "ai_agent" {
				installAllowed = pol.MCP.AIAgentDefaultInstallAllowedOnWarn
			} else {
				installAllowed = pol.MCP.HumanDefaultInstallAllowedOnWarn
			}
		}
	}

	recommendedAction := "Install may proceed."
	if overallDecision == "block" {
		recommendedAction = "Install is blocked due to critical risk findings."
	} else if overallDecision == "warn" {
		recommendedAction = "Review warnings and risks before proceeding."
	}
	decision := types.Decision(overallDecision)
	instruction := agentInstruction(decision, installAllowed, p.RequestedBy, pol.Mode)

	toolRes := ValidateInstallCommandResult{
		Command:           p.Command,
		Ecosystem:         ecosystem,
		Decision:          overallDecision,
		InstallAllowed:    installAllowed,
		Packages:          packages,
		RecommendedAction: recommendedAction,
		AgentInstruction:  instruction,
	}

	auditPackages := make([]intercept.AuditPackage, 0, len(packages))
	for _, pkg := range packages {
		auditPackages = append(auditPackages, intercept.AuditPackage{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Decision:  pkg.Decision,
			RiskScore: pkg.RiskScore,
		})
	}
	_ = intercept.LogAudit(pol, intercept.AuditEntry{
		Command:         p.Command,
		Ecosystem:       ecosystem,
		Packages:        auditPackages,
		Mode:            string(pol.Mode),
		InstallExecuted: false,
		OverrideUsed:    false,
		Reason:          fmt.Sprintf("mcp validate_install_command requested_by=%s action=%s allowed=%t", p.RequestedBy, instruction.Action, installAllowed),
	})

	bResult, _ := json.MarshalIndent(toolRes, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(bResult),
		}},
		IsError: false,
	}
}
