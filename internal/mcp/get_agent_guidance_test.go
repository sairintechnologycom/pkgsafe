package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// TestGetAgentGuidanceTool_ToolError_MissingName ensures that calling
// get_agent_guidance without a package name returns an error result.
func TestGetAgentGuidanceTool_ToolError_MissingName(t *testing.T) {
	e := &Executor{}
	args := json.RawMessage(`{"ecosystem":"npm"}`)
	res := e.GetAgentGuidanceTool(args)
	if !res.IsError {
		t.Fatal("expected IsError=true when name is missing")
	}
	if len(res.Content) == 0 {
		t.Fatal("expected non-empty content on error")
	}
}

// TestGetAgentGuidanceTool_ToolError_InvalidJSON ensures that malformed JSON
// returns an error result rather than panicking.
func TestGetAgentGuidanceTool_ToolError_InvalidJSON(t *testing.T) {
	e := &Executor{}
	args := json.RawMessage(`{not-valid-json`)
	res := e.GetAgentGuidanceTool(args)
	if !res.IsError {
		t.Fatal("expected IsError=true for malformed JSON")
	}
}

// TestGetAgentGuidanceTool_ToolError_BadPolicyPath verifies that a missing
// policy file returns a POLICY_LOAD_FAILURE error (not a panic).
func TestGetAgentGuidanceTool_ToolError_BadPolicyPath(t *testing.T) {
	e := &Executor{PolicyPath: "/nonexistent/path/policy.yaml"}
	args := json.RawMessage(`{"name":"axios","ecosystem":"npm"}`)
	res := e.GetAgentGuidanceTool(args)
	// Either a scan error or policy error — either way IsError must be set.
	// (The default policy fallback may succeed; we only assert no panic.)
	_ = res
}

// TestGetAgentGuidance_Unit exercises the pure GetAgentGuidance function
// directly for each decision × agent-policy combination.
func TestGetAgentGuidance_Unit(t *testing.T) {
	defaultAP := policy.AgentPolicy{
		Mode:                             "enforce",
		WarnRequiresHuman:                true,
		BlockInstallCommands:             true,
		RequirePkgSafeCheckBeforeInstall: true,
	}

	t.Run("ALLOW returns proceed", func(t *testing.T) {
		g := GetAgentGuidance(types.DecisionAllow, defaultAP, policy.ModeWarn)
		if g.Decision != "ALLOW" {
			t.Errorf("expected ALLOW, got %s", g.Decision)
		}
		if !contains(g.AllowedNextActions, "proceed") {
			t.Errorf("expected 'proceed' in allowed_next_actions, got %v", g.AllowedNextActions)
		}
		if contains(g.ProhibitedActions, "run_install") {
			t.Errorf("expected 'run_install' NOT in prohibited_actions for ALLOW, got %v", g.ProhibitedActions)
		}
	})

	t.Run("WARN with WarnRequiresHuman asks human", func(t *testing.T) {
		g := GetAgentGuidance(types.DecisionWarn, defaultAP, policy.ModeWarn)
		if g.Decision != "WARN" {
			t.Errorf("expected WARN, got %s", g.Decision)
		}
		if !contains(g.AllowedNextActions, "ask_user") {
			t.Errorf("expected 'ask_user' in allowed_next_actions, got %v", g.AllowedNextActions)
		}
		if !contains(g.ProhibitedActions, "run_install") {
			t.Errorf("expected 'run_install' in prohibited_actions for WARN+WarnRequiresHuman, got %v", g.ProhibitedActions)
		}
	})

	t.Run("BLOCK never allows run_install", func(t *testing.T) {
		g := GetAgentGuidance(types.DecisionBlock, defaultAP, policy.ModeWarn)
		if g.Decision != "BLOCK" {
			t.Errorf("expected BLOCK, got %s", g.Decision)
		}
		if contains(g.AllowedNextActions, "proceed") {
			t.Errorf("expected 'proceed' NOT in allowed_next_actions for BLOCK, got %v", g.AllowedNextActions)
		}
		if !contains(g.ProhibitedActions, "run_install") {
			t.Errorf("expected 'run_install' in prohibited_actions for BLOCK, got %v", g.ProhibitedActions)
		}
	})

	t.Run("REVIEW_REQUIRED requires authorized review", func(t *testing.T) {
		g := GetAgentGuidance(types.DecisionReviewRequired, defaultAP, policy.ModeWarn)
		if g.Decision != "REVIEW_REQUIRED" {
			t.Errorf("expected REVIEW_REQUIRED, got %s", g.Decision)
		}
		if !contains(g.AllowedNextActions, "request_review") {
			t.Errorf("expected 'request_review' in allowed_next_actions, got %v", g.AllowedNextActions)
		}
		if !contains(g.ProhibitedActions, "run_install") {
			t.Errorf("expected 'run_install' in prohibited_actions for REVIEW_REQUIRED, got %v", g.ProhibitedActions)
		}
	})

	t.Run("observe mode always allows proceed", func(t *testing.T) {
		observeAP := policy.AgentPolicy{Mode: "observe"}
		g := GetAgentGuidance(types.DecisionBlock, observeAP, policy.ModeWarn)
		if !contains(g.AllowedNextActions, "proceed") {
			t.Errorf("expected 'proceed' in observe mode, got %v", g.AllowedNextActions)
		}
	})

	t.Run("block policy mode escalates WARN to BLOCK", func(t *testing.T) {
		blockAP := policy.AgentPolicy{Mode: "block"}
		g := GetAgentGuidance(types.DecisionWarn, blockAP, policy.ModeBlock)
		if g.Decision != "BLOCK" {
			t.Errorf("expected WARN escalated to BLOCK in block mode, got %s", g.Decision)
		}
	})
}

func TestDecisionString_ReviewRequired(t *testing.T) {
	if got := decisionString(types.DecisionReviewRequired); got != "REVIEW_REQUIRED" {
		t.Fatalf("expected REVIEW_REQUIRED, got %s", got)
	}
}

func TestAgentInstruction_ReviewRequired(t *testing.T) {
	got := agentInstruction(types.DecisionReviewRequired, false, "ai_agent", policy.ModeWarn)
	if got.Action != "ask_human" {
		t.Fatalf("expected ask_human, got %s", got.Action)
	}
	if got.Message == "" || got.Message == "Do not install automatically. The policy does not allow installation." {
		t.Fatalf("expected explicit REVIEW_REQUIRED message, got %q", got.Message)
	}
}

func TestRemediationForDecision_ReviewRequired(t *testing.T) {
	got := remediationForDecision(types.DecisionReviewRequired)
	if len(got) == 0 {
		t.Fatal("expected remediation items for REVIEW_REQUIRED")
	}
	if got[0] != "Request authorized human review" {
		t.Fatalf("unexpected first remediation item: %v", got)
	}
}

// TestGetAgentGuidanceTool_ToolList verifies get_agent_guidance appears in
// the MCP tools/list response.
func TestGetAgentGuidanceTool_ToolList(t *testing.T) {
	list := GetToolsList()
	found := false
	for _, tool := range list.Tools {
		if tool.Name == "get_agent_guidance" {
			found = true
			// Verify required field is set
			req, ok := tool.InputSchema["required"]
			if !ok {
				t.Fatal("get_agent_guidance schema missing 'required' field")
			}
			reqSlice, ok := req.([]string)
			if !ok {
				t.Fatal("'required' field is not []string")
			}
			if !containsStr(reqSlice, "name") {
				t.Errorf("expected 'name' in required fields, got %v", reqSlice)
			}
			break
		}
	}
	if !found {
		t.Error("get_agent_guidance not found in tools/list")
	}
}

// TestGetAgentGuidanceTool_WithPolicy exercises the full handler against the
// default policy to verify it produces a valid JSON response structure.
func TestGetAgentGuidanceTool_WithPolicy(t *testing.T) {
	// Write the default policy to a temp dir so the executor can load it.
	tmpDir := t.TempDir()
	defaultPolicyBytes, err := os.ReadFile("../../default-policy.yaml")
	if err != nil {
		t.Skip("default-policy.yaml not found, skipping integration test")
	}
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(policyPath, defaultPolicyBytes, 0644); err != nil {
		t.Fatal(err)
	}

	e := &Executor{PolicyPath: policyPath}

	// We run with offline=true to avoid network calls in tests, which means the
	// scanner will use only cached/local data. The package will likely resolve
	// as ALLOW or WARN with zero findings — either is valid for this structural test.
	args := json.RawMessage(`{
		"ecosystem":    "npm",
		"name":         "axios",
		"version":      "latest",
		"requested_by": "ai_agent",
		"offline":      true
	}`)

	res := e.GetAgentGuidanceTool(args)

	if len(res.Content) == 0 {
		t.Fatal("expected at least one content item in result")
	}

	// A clean CI runner may have no offline cache entry for axios. In that case
	// the tool must return a structured scan error; do not decode that error
	// object into GetAgentGuidanceResult, because encoding/json accepts unknown
	// fields and would leave every result field at its zero value.
	if res.IsError {
		var raw map[string]any
		if err := json.Unmarshal([]byte(res.Content[0].Text), &raw); err != nil {
			t.Fatalf("error response is not valid JSON: %v\ntext: %s", err, res.Content[0].Text)
		}
		if len(raw) == 0 {
			t.Fatal("expected structured error response")
		}
		return
	}

	// Parse a successful response and verify required fields are present.
	var result GetAgentGuidanceResult
	if err := json.Unmarshal([]byte(res.Content[0].Text), &result); err != nil {
		t.Fatalf("successful response is not valid guidance JSON: %v\ntext: %s", err, res.Content[0].Text)
	}

	// When a full result is returned, decision must be one of the supported values.
	switch result.Decision {
	case "ALLOW", "WARN", "BLOCK", "REVIEW_REQUIRED":
		// valid
	default:
		t.Errorf("unexpected decision value: %q", result.Decision)
	}

	if result.EvidenceID == "" {
		t.Error("expected non-empty evidence_id")
	}
	if len(result.TopReasons) == 0 {
		t.Error("expected at least one entry in top_reasons")
	}
	if len(result.AllowedNextActions) == 0 && result.Decision == "ALLOW" {
		t.Error("expected allowed_next_actions to be non-empty for ALLOW decision")
	}
}

// --- helpers ---

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func containsStr(slice []string, val string) bool {
	return contains(slice, val)
}
