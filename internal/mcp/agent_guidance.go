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
