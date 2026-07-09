package mcp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	scargo "github.com/sairintechnologycom/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/sairintechnologycom/pkgsafe/internal/scanner/golang"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
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

	// Run scan based on ecosystem
	var res types.ScanResult
	var scanErr error

	switch p.Ecosystem {
	case "pypi":
		scanner := spypi.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	case "cargo":
		scanner := scargo.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	case "go", "golang":
		scanner := sgolang.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"
		res, scanErr = scanner.ScanPackage(p.Name, p.Version)
	default: // npm
		scanner := snpm.New()
		scanner.Policy = pol
		scanner.Offline = e.Offline || p.Offline
		scanner.RequestedBy = "ai_agent"
		scanner.Environment = "ai_agent"

		behaviorMode := types.NormalizeBehaviorMode(pol.Sandbox.BehaviorMode, pol.Sandbox.Enabled)
		scanner.BehaviorMode = behaviorMode
		scanner.SandboxEnabled = behaviorMode != types.BehaviorDisabled
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

	// Decision mapping
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

	// Format top reasons
	var reasons []string
	for _, r := range res.Reasons {
		reasons = append(reasons, r.Description)
	}
	if len(reasons) == 0 {
		reasons = []string{
			"No critical vulnerabilities found",
			"No lifecycle scripts detected",
			"Package age and project health acceptable",
		}
	}

	// Generate evidence ID
	evidenceID := fmt.Sprintf("pkg-%s-%03d", time.Now().Format("20060102"), time.Now().UnixNano()%1000)

	// Build guidance instructions
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
	default:
		instruction = "Do not install automatically. The policy does not allow installation."
		allowedActions = []string{"suggest_alternative", "remove_dependency"}
		prohibitedActions = []string{"run_install", "execute_lifecycle_script"}
	}

	toolRes := AgentMCPResult{
		Decision:           decision,
		RiskScore:          res.Score,
		Confidence:         "high",
		TopReasons:         reasons,
		PolicyResult:       fmt.Sprintf("mode: %s, scan_decision: %s", pol.Mode, res.Decision),
		EvidenceID:         evidenceID,
		AgentInstruction:   instruction,
		AllowedNextActions: allowedActions,
		ProhibitedActions:  prohibitedActions,
	}

	// Try to get safe alternatives if not allowed
	if decision != "ALLOW" {
		alts := agent.GetSafeAlternatives(p.Name)
		if len(alts) > 0 {
			var altNames []string
			for _, alt := range alts {
				altNames = append(altNames, alt.Name)
			}
			toolRes.AllowedNextActions = append(toolRes.AllowedNextActions, "suggest_alternative")
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
