package mcp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ExplainPolicyDecisionParams defines parameters for explain_policy_decision.
type ExplainPolicyDecisionParams struct {
	Package  string `json:"package"`
	Decision string `json:"decision"`
	RepoPath string `json:"repo_path"`
}

// ExplainPolicyDecisionResult defines the detailed output.
type ExplainPolicyDecisionResult struct {
	Decision           string               `json:"decision"`
	RiskScore          int                  `json:"risk_score"`
	Confidence         string               `json:"confidence"`
	TopReasons         []string             `json:"top_reasons"`
	PackageProfile     types.PackageProfile `json:"package_profile"`
	PolicyResult       string               `json:"policy_result"`
	EvidenceID         string               `json:"evidence_id"`
	AgentInstruction   string               `json:"agent_instruction"`
	AllowedNextActions []string             `json:"allowed_next_actions"`
	ProhibitedActions  []string             `json:"prohibited_actions"`
	RuleIDs            []string             `json:"rule_ids"`
	Remediation        []string             `json:"remediation"`
}

// ExplainPolicyDecision explains why a package is safe, suspicious, or blocked.
func (e *Executor) ExplainPolicyDecision(args json.RawMessage) CallToolResult {
	var p ExplainPolicyDecisionParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
			}},
			IsError: true,
		}
	}

	if p.Package == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("MISSING_PACKAGE", "Package name or specifier is required", nil),
			}},
			IsError: true,
		}
	}

	// Parse package specifier (e.g. npm:express@1.0.0 or express@1.0.0 or express)
	ecosystem := "npm"
	spec := p.Package
	if parts := strings.SplitN(spec, ":", 2); len(parts) == 2 {
		ecosystem = parts[0]
		spec = parts[1]
	}
	name := spec
	version := "latest"
	if parts := strings.SplitN(spec, "@", 2); len(parts) == 2 {
		name = parts[0]
		version = parts[1]
	}

	ecosystem = strings.ToLower(ecosystem)
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

	opts := ScanOpts{
		RequestedBy: "ai_agent",
		Environment: "ai_agent",
	}
	res, _, err := e.evaluatePackage(ecosystem, name, version, pol, e.Offline, "ai_agent", opts)
	if err != nil {
		te := MapScanError(err, ecosystem, name, version)
		b, _ := json.MarshalIndent(te, "", "  ")
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: string(b),
			}},
			IsError: true,
		}
	}

	var ruleIDs []string
	var topReasons []string
	for _, r := range res.Reasons {
		ruleIDs = append(ruleIDs, r.ID)
		topReasons = append(topReasons, r.Description)
	}
	if len(topReasons) == 0 {
		topReasons = []string{"No critical safety findings."}
	}

	remediation := remediationForDecision(res.Decision)

	evidenceID := generateEvidenceID(ecosystem, name, version)
	guidance := GetAgentGuidance(res.Decision, pol.AgentPolicy, pol.Mode)

	toolRes := ExplainPolicyDecisionResult{
		Decision:           guidance.Decision,
		RiskScore:          res.Score,
		Confidence:         "high",
		TopReasons:         topReasons,
		PackageProfile:     res.Profile,
		PolicyResult:       fmt.Sprintf("mode: %s, scan_decision: %s", pol.Mode, res.Decision),
		EvidenceID:         evidenceID,
		AgentInstruction:   guidance.Instruction,
		AllowedNextActions: guidance.AllowedNextActions,
		ProhibitedActions:  guidance.ProhibitedActions,
		RuleIDs:            ruleIDs,
		Remediation:        remediation,
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

func remediationForDecision(decision types.Decision) []string {
	switch decision {
	case types.DecisionBlock:
		return []string{"Remove dependency", "Use approved internal package", "Request security exception"}
	case types.DecisionWarn:
		return []string{"Request human approval", "Request policy exception", "Use a safer alternative"}
	case types.DecisionReviewRequired:
		return []string{"Request authorized human review", "Do not install automatically", "Use a safer alternative if available"}
	default:
		return []string{"No remediation required"}
	}
}
