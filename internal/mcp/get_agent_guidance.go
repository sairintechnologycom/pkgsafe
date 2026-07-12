package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// GetAgentGuidanceParams defines the input parameters for the get_agent_guidance MCP tool.
type GetAgentGuidanceParams struct {
	// Ecosystem of the package (npm, pypi, go, cargo).
	Ecosystem string `json:"ecosystem"`
	// Name of the package to evaluate.
	Name string `json:"name"`
	// Version of the package. Defaults to "latest".
	Version string `json:"version"`
	// RequestedBy identifies the caller: "human" or "ai_agent".
	RequestedBy string `json:"requested_by"`
	// RepoPath is an optional local project path used to resolve a project-level policy.
	RepoPath string `json:"repo_path"`
	// Offline forces the scan to use only locally cached data.
	Offline bool `json:"offline"`
}

// GetAgentGuidanceResult is the response returned by the get_agent_guidance MCP tool.
type GetAgentGuidanceResult struct {
	// Decision is the top-level safety verdict: ALLOW, WARN, BLOCK, or REVIEW_REQUIRED.
	Decision string `json:"decision"`
	// RiskScore is the numeric risk score (0–100).
	RiskScore int `json:"risk_score"`
	// AgentInstruction is a plain-English directive for the agent.
	AgentInstruction string `json:"agent_instruction"`
	// AllowedNextActions lists actions the agent is permitted to take.
	AllowedNextActions []string `json:"allowed_next_actions"`
	// ProhibitedActions lists actions the agent must not take.
	ProhibitedActions []string `json:"prohibited_actions"`
	// EvidenceID is a stable ID linking this result to the audit log.
	EvidenceID string `json:"evidence_id"`
	// TopReasons is a human-readable summary of the top risk findings.
	TopReasons []string `json:"top_reasons"`
	// PolicyMode is the active enforcement mode (audit, warn, block).
	PolicyMode string `json:"policy_mode"`
}

// GetAgentGuidanceTool runs a full package scan and returns structured agent
// guidance — allowed/prohibited actions, a plain-English instruction, and the
// underlying risk score — all shaped by the active policy's AgentPolicy section.
//
// This is the preferred tool for agent orchestrators (Claude Code, Cursor, etc.)
// that need deterministic, policy-driven next-action guidance rather than raw
// scan details.
func (e *Executor) GetAgentGuidanceTool(args json.RawMessage) CallToolResult {
	var p GetAgentGuidanceParams
	if err := json.Unmarshal(args, &p); err != nil {
		return toolError(serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil))
	}

	// Apply defaults
	if p.Ecosystem == "" {
		p.Ecosystem = "npm"
	}
	p.Ecosystem = strings.ToLower(p.Ecosystem)

	if p.Name == "" {
		return toolError(serializeError("MISSING_PACKAGE_NAME", "Package name is required", nil))
	}
	if p.Version == "" {
		p.Version = "latest"
	}
	if p.RequestedBy == "" {
		p.RequestedBy = "ai_agent"
	}
	if p.RepoPath == "" {
		p.RepoPath = "."
	}

	// Resolve policy (project-local first, then executor default)
	policyFile := filepath.Join(p.RepoPath, ".pkgsafe/policy.yaml")
	pol, err := policy.ResolvePolicy("", policyFile, e.PolicyPath, "", "")
	if err != nil {
		return toolError(serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil))
	}

	// Run full scan + enterprise-control pass
	opts := ScanOpts{
		RequestedBy: p.RequestedBy,
		Environment: p.RequestedBy,
	}
	res, installAllowed, scanErr := e.evaluatePackage(p.Ecosystem, p.Name, p.Version, pol, p.Offline, p.RequestedBy, opts)
	if scanErr != nil {
		te := MapScanError(scanErr, p.Ecosystem, p.Name, p.Version)
		b, _ := json.MarshalIndent(te, "", "  ")
		return toolError(string(b))
	}

	// Build structured guidance from the policy's AgentPolicy config
	guidance := GetAgentGuidance(res.Decision, pol.AgentPolicy, pol.Mode)

	// When the scan allows but install is blocked by policy mode, reflect that
	if !installAllowed && guidance.Decision == "ALLOW" {
		guidance.Decision = "WARN"
		guidance.Instruction = "Policy mode restricts installation. Ask a human before proceeding."
		guidance.AllowedNextActions = []string{"ask_user"}
		guidance.ProhibitedActions = []string{"run_install", "execute_lifecycle_script"}
	}

	// Collect top reasons
	var reasons []string
	for _, r := range res.Reasons {
		reasons = append(reasons, r.Description)
	}
	if len(reasons) == 0 {
		reasons = []string{"No findings recorded"}
	}

	result := GetAgentGuidanceResult{
		Decision:           guidance.Decision,
		RiskScore:          res.Score,
		AgentInstruction:   guidance.Instruction,
		AllowedNextActions: guidance.AllowedNextActions,
		ProhibitedActions:  guidance.ProhibitedActions,
		EvidenceID:         generateEvidenceID(p.Ecosystem, p.Name, p.Version),
		TopReasons:         reasons,
		PolicyMode:         string(pol.Mode),
	}

	b, _ := json.MarshalIndent(result, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{Type: "text", Text: string(b)}},
		IsError: false,
	}
}

// toolError is a convenience constructor for tool-level error responses.
func toolError(text string) CallToolResult {
	return CallToolResult{
		Content: []ToolContent{{Type: "text", Text: text}},
		IsError: true,
	}
}
