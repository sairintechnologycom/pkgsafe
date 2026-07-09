package mcp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	scargo "github.com/sairintechnologycom/pkgsafe/internal/scanner/cargo"
	sgolang "github.com/sairintechnologycom/pkgsafe/internal/scanner/golang"
	snpm "github.com/sairintechnologycom/pkgsafe/internal/scanner/npm"
	spypi "github.com/sairintechnologycom/pkgsafe/internal/scanner/pypi"
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

	for _, pp := range parsedPkgs {
		var res types.ScanResult
		var err error

		switch pp.Ecosystem {
		case "pypi":
			scanner := spypi.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline || p.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pp.Name, pp.Version)
		case "cargo":
			scanner := scargo.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline || p.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pp.Name, pp.Version)
		case "go", "golang":
			scanner := sgolang.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline || p.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pp.Name, pp.Version)
		default: // npm
			scanner := snpm.New()
			scanner.Policy = pol
			scanner.Offline = e.Offline || p.Offline
			scanner.RequestedBy = "ai_agent"
			scanner.Environment = "ai_agent"
			res, err = scanner.ScanPackage(pp.Name, pp.Version)
		}

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

		pkgDecision := "ALLOW"
		switch res.Decision {
		case types.DecisionBlock:
			pkgDecision = "BLOCK"
			hasBlock = true
		case types.DecisionWarn:
			pkgDecision = "WARN"
			hasWarn = true
		default:
			pkgDecision = "ALLOW"
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

	overallDecision := "ALLOW"
	if hasBlock {
		overallDecision = "BLOCK"
	} else if hasWarn {
		overallDecision = "WARN"
	}

	evidenceID := fmt.Sprintf("pkg-%s-%03d", time.Now().Format("20060102"), time.Now().UnixNano()%1000)

	var instruction string
	var allowedActions []string
	var prohibitedActions []string

	switch overallDecision {
	case "ALLOW":
		instruction = "Command may be run."
		allowedActions = []string{"proceed"}
		prohibitedActions = []string{}
	case "WARN":
		instruction = "Do not run the install command automatically. Ask the user for approval or choose an existing dependency."
		allowedActions = []string{"ask_user", "suggest_alternative", "remove_dependency"}
		prohibitedActions = []string{"run_install", "execute_lifecycle_script"}
	case "BLOCK":
		instruction = "Do not install this package. The policy decision is BLOCK."
		allowedActions = []string{"suggest_alternative", "remove_dependency"}
		prohibitedActions = []string{"run_install", "execute_lifecycle_script"}
	}

	if len(topReasons) == 0 {
		topReasons = []string{"All packages match safety criteria."}
	}

	toolRes := CheckInstallCommandResult{
		Decision:           overallDecision,
		RiskScore:          maxScore,
		Confidence:         "high",
		TopReasons:         topReasons,
		PolicyResult:       fmt.Sprintf("mode: %s", pol.Mode),
		EvidenceID:         evidenceID,
		AgentInstruction:   instruction,
		AllowedNextActions: allowedActions,
		ProhibitedActions:  prohibitedActions,
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
