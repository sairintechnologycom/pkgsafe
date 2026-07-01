package mcp

import (
	"encoding/json"
)

// JSON-RPC 2.0 Request structure.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSON-RPC 2.0 Response structure.
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

// JSON-RPC 2.0 Error structure.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string {
	return e.Message
}

// MCP Initialize Params.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      ClientInfo     `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCP Initialize Result.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

type ServerCapabilities struct {
	Tools struct{} `json:"tools"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CallToolParams is the parameter payload for tools/call.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolContent represents a standard text output format for MCP tool responses.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult is returned as the JSON-RPC Result for tools/call.
type CallToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError"`
}

// Tool definitions for tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type ToolListResult struct {
	Tools []Tool `json:"tools"`
}

func GetToolsList() ToolListResult {
	return ToolListResult{
		Tools: []Tool{
			{
				Name:        "validate_package_install",
				Description: "Validate whether a package should be installed. For AI agents, BLOCK means never install and WARN means ask a human before installing.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ecosystem": map[string]any{
							"type":        "string",
							"enum":        []string{"npm", "pypi"},
							"description": "Package ecosystem",
							"default":     "npm",
						},
						"name": map[string]any{
							"type":        "string",
							"description": "The name of the package to validate",
						},
						"version": map[string]any{
							"type":        "string",
							"description": "The package version (e.g. latest, 1.0.0)",
							"default":     "latest",
						},
						"requested_by": map[string]any{
							"type":        "string",
							"enum":        []string{"human", "ai_agent"},
							"description": "Who is requesting the package installation (human or ai_agent)",
							"default":     "human",
						},
						"project_path": map[string]any{
							"type":        "string",
							"description": "Optional absolute path to the local project",
						},
						"mode": map[string]any{
							"type":        "string",
							"enum":        []string{"audit", "warn", "block"},
							"description": "Optional scan mode to override policy defaults",
						},
						"offline": map[string]any{
							"type":        "boolean",
							"description": "Run the validation offline using cached database and metadata",
							"default":     false,
						},
						"behavior_mode": map[string]any{
							"type":        "string",
							"enum":        []string{"disabled", "heuristic", "isolated"},
							"description": "Behavior analysis mode. Heuristic runs lifecycle scripts on the host without isolation; isolated is experimental, Linux-only, and requires bubblewrap.",
							"default":     "disabled",
						},
						"sandbox": map[string]any{
							"type":        "boolean",
							"description": "Deprecated compatibility alias for behavior_mode=heuristic. NOTE: scripts run on the host without OS isolation; this is not a security sandbox.",
							"default":     false,
						},
						"sandbox_timeout_seconds": map[string]any{
							"type":        "integer",
							"description": "Timeout for lifecycle-script behavior analysis, in seconds",
							"default":     10,
						},
						"network_mode": map[string]any{
							"type":        "string",
							"enum":        []string{"disabled", "limited", "host"},
							"description": "Declared network mode for behavior analysis (advisory only; not enforced — network is not actually isolated)",
							"default":     "disabled",
						},
					},
					"required": []string{"name"},
				},
			},
			{
				Name:        "explain_package_risk",
				Description: "Explain why a package is safe, suspicious, or blocked.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ecosystem": map[string]any{
							"type":        "string",
							"enum":        []string{"npm", "pypi"},
							"description": "Package ecosystem",
							"default":     "npm",
						},
						"name": map[string]any{
							"type":        "string",
							"description": "The name of the package",
						},
						"version": map[string]any{
							"type":        "string",
							"description": "The package version",
							"default":     "latest",
						},
						"offline": map[string]any{
							"type":        "boolean",
							"description": "Run explain offline",
							"default":     false,
						},
					},
					"required": []string{"name"},
				},
			},
			{
				Name:        "score_lockfile",
				Description: "Score an npm lockfile for risky direct and transitive dependencies.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{
							"type":        "string",
							"description": "Absolute path to the package-lock.json file",
						},
						"ecosystem": map[string]any{
							"type":        "string",
							"enum":        []string{"npm"},
							"description": "Package lock ecosystem",
							"default":     "npm",
						},
						"mode": map[string]any{
							"type":        "string",
							"enum":        []string{"audit", "warn", "block"},
							"description": "Optional policy enforcement mode",
						},
						"offline": map[string]any{
							"type":        "boolean",
							"description": "Run the lockfile scan offline using the local vulnerability database",
							"default":     false,
						},
					},
					"required": []string{"path"},
				},
			},
			{
				Name:        "suggest_safe_alternative",
				Description: "Suggest safer alternative packages when a package is risky, unknown, hallucinated, or suspicious.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ecosystem": map[string]any{
							"type":    "string",
							"enum":    []string{"npm"},
							"default": "npm",
						},
						"requested_package": map[string]any{
							"type":        "string",
							"description": "The package name that is being queried for alternatives",
						},
						"intent": map[string]any{
							"type":        "string",
							"description": "Optional description of what the package is used for (e.g. 'markdown renderer')",
						},
						"max_results": map[string]any{
							"type":    "integer",
							"default": 5,
						},
					},
					"required": []string{"requested_package"},
				},
			},
			{
				Name:        "validate_install_command",
				Description: "Extract and validate packages from a full install command string. For AI agents, BLOCK means never install and WARN means ask a human before installing.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"command": map[string]any{
							"type":        "string",
							"description": "The npm or pip install command string to extract packages from",
						},
						"requested_by": map[string]any{
							"type":        "string",
							"enum":        []string{"human", "ai_agent"},
							"description": "Who is requesting the package installation",
							"default":     "ai_agent",
						},
						"project_path": map[string]any{
							"type":        "string",
							"description": "Optional local project path",
						},
						"mode": map[string]any{
							"type":        "string",
							"enum":        []string{"audit", "warn", "block"},
							"description": "Optional policy enforcement mode",
						},
						"offline": map[string]any{
							"type":        "boolean",
							"description": "Run validation offline using local database",
							"default":     false,
						},
					},
					"required": []string{"command"},
				},
			},
			{
				Name:        "generate_governance_report",
				Description: "Generate a structured PkgSafe governance evidence report for a repository.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"repo_path": map[string]any{
							"type":        "string",
							"description": "Path to the repository root directory",
							"default":     ".",
						},
						"format": map[string]any{
							"type":        "string",
							"enum":        []string{"json", "markdown", "html", "all"},
							"description": "Output format of the report",
							"default":     "json",
						},
						"include_audit_log": map[string]any{
							"type":        "boolean",
							"description": "Include override details from the developer audit log",
							"default":     true,
						},
					},
				},
			},
			{
				Name:        "get_recent_package_decisions",
				Description: "Retrieve recent dependency safety decisions from PkgSafe's audit logs.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"limit": map[string]any{
							"type":        "integer",
							"description": "Maximum number of decisions to return",
							"default":     10,
						},
						"ecosystem": map[string]any{
							"type":        "string",
							"enum":        []string{"npm", "pypi"},
							"description": "Filter decisions by package ecosystem",
						},
					},
				},
			},
			{
				Name:        "get_policy_evidence",
				Description: "Get evidence of active security policies, rules, and control settings.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"policy_pack": map[string]any{
							"type":        "string",
							"description": "Optional policy pack name to check",
						},
					},
				},
			},
		},
	}
}

func errResp(id any, code int, msg string) Response {
	return Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}
