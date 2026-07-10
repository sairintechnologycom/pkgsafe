package mcp

import (
	"fmt"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type AgentInstruction struct {
	Action  string `json:"action"`
	Message string `json:"message"`
}

// AgentGuidance is the structured guidance returned by GetAgentGuidance.
type AgentGuidance struct {
	Decision           string   `json:"decision"`
	Instruction        string   `json:"agent_instruction"`
	AllowedNextActions []string `json:"allowed_next_actions"`
	ProhibitedActions  []string `json:"prohibited_actions"`
}

// GetAgentGuidance returns unified, type-safe agent guidance from a scan decision and policy.
func GetAgentGuidance(decision types.Decision, ap policy.AgentPolicy, pm policy.Mode) AgentGuidance {
	var allowed []string
	var prohibited []string
	decStr := decisionToUpper(decision)

	// Observe mode overrides
	if ap.Mode == "observe" {
		instruction := fmt.Sprintf("Decision is %s but agent policy is in observe mode. You may proceed.", decStr)
		if ap.RequirePkgSafeCheckBeforeInstall {
			instruction += " A pre-install check is strictly required before proceeding."
		}
		return AgentGuidance{
			Decision:           decStr,
			Instruction:        instruction,
			AllowedNextActions: []string{"proceed"},
			ProhibitedActions:  []string{},
		}
	}

	// Block override: escalate WARN → BLOCK when agent policy mode is "block"
	if ap.Mode == "block" && (decision == types.DecisionWarn) {
		decStr = "BLOCK"
	}

	var instruction string
	switch decStr {
	case "ALLOW":
		instruction = "Package may be installed."
		allowed = []string{"proceed"}
		prohibited = []string{}
	case "WARN":
		if ap.WarnRequiresHuman {
			instruction = "Do not install automatically. Ask the user for approval or choose an existing dependency. Human confirmation is REQUIRED."
			allowed = []string{"ask_user", "suggest_alternative", "remove_dependency"}
			prohibited = []string{"run_install", "execute_lifecycle_script"}
		} else {
			instruction = "Warning detected, but policy allows proceeding under exception."
			allowed = []string{"proceed", "suggest_alternative", "remove_dependency"}
			prohibited = []string{}
		}
	case "BLOCK":
		instruction = "Do not install this package. The policy decision is BLOCK."
		allowed = []string{"suggest_alternative", "remove_dependency"}
		prohibited = []string{"run_install", "execute_lifecycle_script"}
	default:
		instruction = "Do not install automatically. The policy does not allow installation."
		allowed = []string{"suggest_alternative", "remove_dependency"}
		prohibited = []string{"run_install", "execute_lifecycle_script"}
	}

	if ap.BlockInstallCommands && decStr != "ALLOW" {
		prohibited = append(prohibited, "run_install")
		var cleanAllowed []string
		for _, a := range allowed {
			if a != "proceed" {
				cleanAllowed = append(cleanAllowed, a)
			}
		}
		allowed = cleanAllowed
	}

	if ap.RequirePkgSafeCheckBeforeInstall {
		instruction += " A pre-install check is strictly required before proceeding."
	}

	return AgentGuidance{
		Decision:           decStr,
		Instruction:        instruction,
		AllowedNextActions: dedup(allowed),
		ProhibitedActions:  dedup(prohibited),
	}
}

// agentInstruction is a legacy helper for validate_package_install.go.
func agentInstruction(decision types.Decision, installAllowed bool, requestedBy string, mode policy.Mode) AgentInstruction {
	switch decision {
	case types.DecisionBlock:
		return AgentInstruction{
			Action:  "never_install",
			Message: "Do not install this package. The policy decision is BLOCK.",
		}
	case types.DecisionWarn:
		if requestedBy == "ai_agent" && !installAllowed {
			return AgentInstruction{
				Action:  "ask_human",
				Message: "Do not install automatically. Ask a human to review the WARN decision.",
			}
		}
		if !installAllowed {
			return AgentInstruction{
				Action:  "never_install",
				Message: fmt.Sprintf("Do not install automatically. The active policy mode %q blocks WARN decisions.", mode),
			}
		}
		return AgentInstruction{
			Action:  "ask_human",
			Message: "WARN decision: install only after human review.",
		}
	default:
		if installAllowed {
			return AgentInstruction{
				Action:  "proceed",
				Message: "Policy allows installation.",
			}
		}
		return AgentInstruction{
			Action:  "never_install",
			Message: "Do not install automatically. The policy does not allow installation.",
		}
	}
}

// dedup removes duplicate strings while preserving order.
func dedup(lst []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range lst {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

// decisionToUpper maps internal lowercase types.Decision values to their
// uppercase API contract strings (ALLOW / WARN / BLOCK).
func decisionToUpper(d types.Decision) string {
	switch d {
	case types.DecisionAllow:
		return "ALLOW"
	case types.DecisionWarn:
		return "WARN"
	case types.DecisionBlock:
		return "BLOCK"
	default:
		return "BLOCK"
	}
}
