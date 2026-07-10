package mcp

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// CheckInstallCommandParams defines input for check_install_command.
type CheckInstallCommandParams struct {
	Command  string `json:"command"`
	RepoPath string `json:"repo_path"`
	Agent    string `json:"agent"`
	Offline  bool   `json:"offline"`
}

// DetectedPackage represents a single parsed and scanned package.
type DetectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Decision  string `json:"decision"`
	RiskScore int    `json:"risk_score"`
}

// CheckInstallCommandResult defines the tool output.
type CheckInstallCommandResult struct {
	Decision           string            `json:"decision"`
	RiskScore          int               `json:"risk_score"`
	Confidence         string            `json:"confidence"`
	TopReasons         []string          `json:"top_reasons"`
	PolicyResult       string            `json:"policy_result"`
	EvidenceID         string            `json:"evidence_id"`
	AgentInstruction   string            `json:"agent_instruction"`
	AllowedNextActions []string          `json:"allowed_next_actions"`
	ProhibitedActions  []string          `json:"prohibited_actions"`
	PackagesDetected   []DetectedPackage `json:"packages_detected"`
	SafeCommand        *string           `json:"safe_command"`
}

// CheckInstallCommand extracts and scans packages in an install command string.
func (e *Executor) CheckInstallCommand(args json.RawMessage) CallToolResult {
	var p CheckInstallCommandParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.Command == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("MISSING_COMMAND", "Command is required", nil),
			}},
			IsError: true,
		}
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

	if p.RepoPath == "" {
		p.RepoPath = "."
	}

	policyFile := filepath.Join(p.RepoPath, ".pkgsafe/policy.yaml")
	pol, err := policy.ResolvePolicy("", policyFile, e.PolicyPath, "", "")
	if err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("POLICY_LOAD_FAILURE", "Failed to load policy: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	var detected []DetectedPackage
	maxScore := 0
	hasBlock := false
	hasWarn := false
	var topReasons []string

	opts := ScanOpts{
		RequestedBy: "ai_agent",
		Environment: "ai_agent",
	}

	for _, pp := range parsedPkgs {
		res, _, err := e.evaluatePackage(pp.Ecosystem, pp.Name, pp.Version, pol, p.Offline, "ai_agent", opts)
		if err != nil {
			te := MapScanError(err, pp.Ecosystem, pp.Name, pp.Version)
			bErr, _ := json.MarshalIndent(te, "", "  ")
			return CallToolResult{
				Content: []ToolContent{{
					Type: "text",
					Text: string(bErr),
				}},
				IsError: true,
			}
		}

		pkgDecision := decisionString(res.Decision)
		switch res.Decision {
		case types.DecisionBlock:
			hasBlock = true
		case types.DecisionWarn:
			hasWarn = true
		}

		if res.Score > maxScore {
			maxScore = res.Score
		}

		for _, r := range res.Reasons {
			topReasons = append(topReasons, fmt.Sprintf("[%s] %s", pp.Name, r.Description))
		}

		detected = append(detected, DetectedPackage{
			Ecosystem: pp.Ecosystem,
			Name:      pp.Name,
			Version:   pp.Version,
			Decision:  pkgDecision,
			RiskScore: res.Score,
		})
	}

	overallDecision := types.DecisionAllow
	if hasBlock {
		overallDecision = types.DecisionBlock
	} else if hasWarn {
		overallDecision = types.DecisionWarn
	}

	evidenceID := generateEvidenceID("cmd", p.Command, "")

	// Unified guidance via GetAgentGuidance
	guidance := GetAgentGuidance(overallDecision, pol.AgentPolicy, pol.Mode)

	instruction := guidance.Instruction
	if guidance.Decision == string(types.DecisionAllow) {
		instruction = "Command may be run."
	}

	if len(topReasons) == 0 {
		topReasons = []string{"All packages match safety criteria."}
	}

	toolRes := CheckInstallCommandResult{
		Decision:           guidance.Decision,
		RiskScore:          maxScore,
		Confidence:         "high",
		TopReasons:         topReasons,
		PolicyResult:       fmt.Sprintf("mode: %s", pol.Mode),
		EvidenceID:         evidenceID,
		AgentInstruction:   instruction,
		AllowedNextActions: guidance.AllowedNextActions,
		ProhibitedActions:  guidance.ProhibitedActions,
		PackagesDetected:   detected,
		SafeCommand:        nil,
	}

	bResult, _ := json.MarshalIndent(toolRes, "", "  ")
	return CallToolResult{
		Content: []ToolContent{{
			Type: "text",
			Text: string(bResult),
		}},
		IsError: false,
	}
}
