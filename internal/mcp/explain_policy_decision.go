package mcp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	scargo "github.com/sairintechnologycom/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/sairintechnologycom/pkgsafe/internal/scanner/golang"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
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
	Decision           string   `json:"decision"`
	RiskScore          int      `json:"risk_score"`
	Confidence         string   `json:"confidence"`
	TopReasons         []string `json:"top_reasons"`
	PolicyResult       string   `json:"policy_result"`
	EvidenceID         string   `json:"evidence_id"`
	AgentInstruction   string   `json:"agent_instruction"`
	AllowedNextActions []string `json:"allowed_next_actions"`
	ProhibitedActions  []string `json:"prohibited_actions"`
	RuleIDs            []string `json:"rule_ids"`
	Remediation        []string `json:"remediation"`
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

	var res types.ScanResult
	var scanErr error

	switch ecosystem {
	case "pypi":
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(name, version)
	case "cargo":
		scanner := scargo.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(name, version)
	case "go", "golang":
		scanner := sgolang.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(name, version)
	default: // npm
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(name, version)
	}

	if scanErr != nil {
		te := MapScanError(scanErr, ecosystem, name, version)
		b, _ := json.MarshalIndent(te, "", "  ")
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: string(b),
			}},
			IsError: true,
		}
	}

	decision := "ALLOW"
	switch res.Decision {
	case types.DecisionBlock:
		decision = "BLOCK"
	case types.DecisionWarn:
		decision = "WARN"
	case types.DecisionAllow:
		decision = "ALLOW"
	default:
		decision = "BLOCK"
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

	var remediation []string
	switch decision {
	case "BLOCK":
		remediation = []string{"Remove dependency", "Use approved internal package", "Request security exception"}
	case "WARN":
		remediation = []string{"Request human approval", "Request policy exception", "Use a safer alternative"}
	default:
		remediation = []string{"No remediation required"}
	}

	evidenceID := fmt.Sprintf("pkg-%s-%03d", time.Now().Format("20060102"), time.Now().UnixNano()%1000)

	var instruction string
	var allowedActions []string
	var prohibitedActions []string

	switch decision {
	case "ALLOW":
		instruction = "Package may be installed."
		allowedActions = []string{"proceed"}
		prohibitedActions = []string{}
	case "WARN":
		instruction = "Do not install automatically. Ask the user for approval or choose an existing dependency."
		allowedActions = []string{"ask_user", "suggest_alternative", "remove_dependency"}
		prohibitedActions = []string{"run_install", "execute_lifecycle_script"}
	case "BLOCK":
		instruction = "Do not install this package. The policy decision is BLOCK."
		allowedActions = []string{"suggest_alternative", "remove_dependency"}
		prohibitedActions = []string{"run_install", "execute_lifecycle_script"}
	}

	toolRes := ExplainPolicyDecisionResult{
		Decision:           decision,
		RiskScore:          res.Score,
		Confidence:         "high",
		TopReasons:         topReasons,
		PolicyResult:       fmt.Sprintf("mode: %s, scan_decision: %s", pol.Mode, res.Decision),
		EvidenceID:         evidenceID,
		AgentInstruction:   instruction,
		AllowedNextActions: allowedActions,
		ProhibitedActions:  prohibitedActions,
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
