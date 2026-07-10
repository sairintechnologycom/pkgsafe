package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ServerConfig defines configuration parameters for starting the MCP server.
type ServerConfig struct {
	PolicyPath string
	Mode       string
	Offline    bool
	LogLevel   string
}

// Executor coordinates calling of specific MCP tools using active config.
type Executor struct {
	PolicyPath string
	Mode       string
	Offline    bool
	LogLevel   string
}

// Serve starts a local MCP stdio server.
func Serve(config ServerConfig, r io.Reader, w io.Writer) error {
	if config.LogLevel == "debug" {
		fmt.Fprintln(os.Stderr, "starting pkgsafe mcp server...")
	}

	exec := &Executor{
		PolicyPath: config.PolicyPath,
		Mode:       config.Mode,
		Offline:    config.Offline,
		LogLevel:   config.LogLevel,
	}

	scanner := bufio.NewScanner(r)
	enc := json.NewEncoder(w)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if config.LogLevel == "debug" {
			fmt.Fprintln(os.Stderr, "received line:", line)
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(Response{
				JSONRPC: "2.0",
				Error:   &Error{Code: -32700, Message: "Parse error: " + err.Error()},
			})
			continue
		}

		resp := exec.Handle(req)
		if req.ID == nil {
			// This was a notification, do not send response
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// Handle routes the JSON-RPC request to the correct handler.
func (e *Executor) Handle(req Request) Response {
	switch req.Method {
	case "ping":
		return Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"ok": true}}

	case "initialize":
		var params InitializeParams
		_ = json.Unmarshal(req.Params, &params)

		result := InitializeResult{
			ProtocolVersion: "2024-11-05",
			ServerInfo: ServerInfo{
				Name:    "pkgsafe",
				Version: "0.1.0",
			},
		}
		result.Capabilities.Tools = struct{}{}
		return Response{JSONRPC: "2.0", ID: req.ID, Result: result}

	case "notifications/initialized":
		return Response{}

	case "tools/list":
		tools := GetToolsList()
		return Response{JSONRPC: "2.0", ID: req.ID, Result: tools}

	case "tools/call":
		var p CallToolParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req.ID, -32602, "Invalid parameters: "+err.Error())
		}

		var res CallToolResult
		switch p.Name {
		case "validate_package_install":
			res = e.ValidatePackageInstall(p.Arguments)
		case "explain_package_risk":
			res = e.ExplainPackageRisk(p.Arguments)
		case "score_lockfile":
			res = e.ScoreLockfile(p.Arguments)
		case "suggest_safe_alternative":
			res = e.SuggestSafeAlternative(p.Arguments)
		case "validate_install_command":
			res = e.ValidateInstallCommand(p.Arguments)
		case "generate_governance_report":
			res = e.GenerateGovernanceReport(p.Arguments)
		case "get_recent_package_decisions":
			res = e.GetRecentPackageDecisions(p.Arguments)
		case "get_policy_evidence":
			res = e.GetPolicyEvidence(p.Arguments)
		case "check_package":
			res = e.CheckPackage(p.Arguments)
		case "check_install_command":
			res = e.CheckInstallCommand(p.Arguments)
		case "review_dependency_diff":
			res = e.ReviewDependencyDiff(p.Arguments)
		case "explain_policy_decision":
			res = e.ExplainPolicyDecision(p.Arguments)
		case "get_agent_guidance":
			res = e.GetAgentGuidanceTool(p.Arguments)
		case "record_agent_decision":
			res = e.RecordAgentDecision(p.Arguments)
		default:
			return errResp(req.ID, -32601, "Tool not found: "+p.Name)
		}

		return Response{JSONRPC: "2.0", ID: req.ID, Result: res}

	default:
		return errResp(req.ID, -32601, "Method not found: "+req.Method)
	}
}
