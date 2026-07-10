package mcp

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// CheckPackageParams defines parameters for check_package.
type CheckPackageParams struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	RepoPath  string `json:"repo_path"`
	Agent     string `json:"agent"`
	Intent    string `json:"intent"`
	Offline   bool   `json:"offline"`
}

// AgentMCPResult defines the standard agent-facing response structure.
type AgentMCPResult struct {
	Decision           string   `json:"decision"`
	RiskScore          int      `json:"risk_score"`
	Confidence         string   `json:"confidence"`
	TopReasons         []string `json:"top_reasons"`
	PolicyResult       string   `json:"policy_result"`
	EvidenceID         string   `json:"evidence_id"`
	AgentInstruction   string   `json:"agent_instruction"`
	AllowedNextActions []string `json:"allowed_next_actions"`
	ProhibitedActions  []string `json:"prohibited_actions"`
}

// generateEvidenceID returns a collision-resistant evidence ID.
func generateEvidenceID(ecosystem, name, version string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("pkg-%s-%s-%s-%x", ecosystem, name, version, b)
}

// CheckPackage evaluates a package before an agent recommends or installs it.
func (e *Executor) CheckPackage(args json.RawMessage) CallToolResult {
	var p CheckPackageParams
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
	p.Ecosystem = strings.ToLower(p.Ecosystem)
	if p.Ecosystem != "npm" && p.Ecosystem != "pypi" && p.Ecosystem != "go" && p.Ecosystem != "golang" && p.Ecosystem != "cargo" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("UNSUPPORTED_ECOSYSTEM", "Supported ecosystems are npm, pypi, go, cargo", map[string]string{"ecosystem": p.Ecosystem}),
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

	// Use the canonical scanPackage core (no enterprise risk amplification,
	// matching the original CheckPackage lightweight pre-check behavior)
	opts := ScanOpts{
		RequestedBy:  "ai_agent",
		Environment:  "ai_agent",
		RegistryName: "",
	}
	res, scanErr := e.scanPackage(p.Ecosystem, p.Name, p.Version, pol, p.Offline, opts)
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

	// Map internal decision to string
	decision := decisionString(res.Decision)

	// Format top reasons; do not fabricate safety assumptions when empty
	var reasons []string
	for _, r := range res.Reasons {
		reasons = append(reasons, r.Description)
	}
	if len(reasons) == 0 {
		reasons = []string{"No findings recorded"}
	}

	evidenceID := generateEvidenceID(p.Ecosystem, p.Name, p.Version)

	// Build guidance from the unified GetAgentGuidance
	guidance := GetAgentGuidance(res.Decision, pol.AgentPolicy, pol.Mode)

	// Override decision string with guidance's potentially-escalated value
	decision = guidance.Decision

	toolRes := AgentMCPResult{
		Decision:           decision,
		RiskScore:          res.Score,
		Confidence:         "high",
		TopReasons:         reasons,
		PolicyResult:       fmt.Sprintf("mode: %s, scan_decision: %s", pol.Mode, res.Decision),
		EvidenceID:         evidenceID,
		AgentInstruction:   guidance.Instruction,
		AllowedNextActions: guidance.AllowedNextActions,
		ProhibitedActions:  guidance.ProhibitedActions,
	}

	// Append suggest_alternative action when alternatives exist
	if decision != string(types.DecisionAllow) {
		alts := agent.GetSafeAlternatives(p.Name)
		if len(alts) > 0 {
			toolRes.AllowedNextActions = dedup(append(toolRes.AllowedNextActions, "suggest_alternative"))
		}
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

// ApplyAgentPolicyOverrides is kept for backward compatibility with external callers.
// New code should call GetAgentGuidance directly.
func ApplyAgentPolicyOverrides(decision string, ap policy.AgentPolicy) (string, string, []string, []string) {
	// Map string decision back to types.Decision for GetAgentGuidance
	var d types.Decision
	switch decision {
	case "ALLOW":
		d = types.DecisionAllow
	case "WARN":
		d = types.DecisionWarn
	case "BLOCK":
		d = types.DecisionBlock
	default:
		d = types.DecisionBlock
	}
	guidance := GetAgentGuidance(d, ap, "")
	return guidance.Decision, guidance.Instruction, guidance.AllowedNextActions, guidance.ProhibitedActions
}

// decisionString maps a types.Decision to its uppercase string form.
func decisionString(d types.Decision) string {
	switch d {
	case types.DecisionBlock:
		return "BLOCK"
	case types.DecisionWarn:
		return "WARN"
	case types.DecisionAllow:
		return "ALLOW"
	default:
		return "BLOCK"
	}
}
