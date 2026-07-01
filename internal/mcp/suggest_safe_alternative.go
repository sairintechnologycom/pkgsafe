package mcp

import (
	"encoding/json"

	"github.com/sairintechnologycom/pkgsafe/internal/agent"
)

// SuggestSafeAlternativeParams defines input for suggest_safe_alternative.
type SuggestSafeAlternativeParams struct {
	Ecosystem        string `json:"ecosystem"`
	RequestedPackage string `json:"requested_package"`
	Intent           string `json:"intent"`
	MaxResults       int    `json:"max_results"`
}

// SuggestSafeAlternativeResult defines the output schema.
type SuggestSafeAlternativeResult struct {
	Ecosystem        string              `json:"ecosystem"`
	RequestedPackage string              `json:"requested_package"`
	Alternatives     []agent.Alternative `json:"alternatives"`
}

// SuggestSafeAlternative suggests established, safe alternatives for risky package names.
func (e *Executor) SuggestSafeAlternative(args json.RawMessage) CallToolResult {
	var p SuggestSafeAlternativeParams
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
	if p.Ecosystem != "npm" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("UNSUPPORTED_ECOSYSTEM", "Only npm is supported", map[string]string{"ecosystem": p.Ecosystem}),
			}},
			IsError: true,
		}
	}

	if p.RequestedPackage == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "requested_package is required", nil),
			}},
			IsError: true,
		}
	}

	alts := agent.GetSafeAlternatives(p.RequestedPackage)
	if alts == nil {
		alts = []agent.Alternative{}
	}

	if p.MaxResults > 0 && len(alts) > p.MaxResults {
		alts = alts[:p.MaxResults]
	}

	toolRes := SuggestSafeAlternativeResult{
		Ecosystem:        "npm",
		RequestedPackage: p.RequestedPackage,
		Alternatives:     alts,
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
