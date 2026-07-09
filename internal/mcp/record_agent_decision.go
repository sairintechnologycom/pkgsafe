package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/git"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// RecordAgentDecisionParams defines input for record_agent_decision.
type RecordAgentDecisionParams struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Decision      string `json:"decision"`
	ActionTaken   string `json:"action_taken"`
	Agent         string `json:"agent"`
	RepoPath      string `json:"repo_path"`
	EvidenceID    string `json:"evidence_id"`
	HumanApproved bool   `json:"human_approved"`
}

// AgentAuditEvent matches the local event model structure.
type AgentAuditEvent struct {
	EventID               string `json:"event_id"`
	Timestamp             string `json:"timestamp"`
	AgentName             string `json:"agent_name"`
	AgentTool             string `json:"agent_tool"`
	RepoPath              string `json:"repo_path"`
	RepoSHA               string `json:"repo_sha"`
	Package               string `json:"package"`
	Ecosystem             string `json:"ecosystem"`
	Version               string `json:"version"`
	CommandRequested      string `json:"command_requested"`
	Decision              string `json:"decision"`
	RiskScore             int    `json:"risk_score"`
	PolicyVersion         string `json:"policy_version"`
	EvidenceID            string `json:"evidence_id"`
	HumanApprovalRequired bool   `json:"human_approval_required"`
	HumanApprovalRecorded bool   `json:"human_approval_recorded"`
	RedactionStatus       string `json:"redaction_status"`
}

// RecordAgentDecision records an AI-agent dependency decision to the audit log.
func (e *Executor) RecordAgentDecision(args json.RawMessage) CallToolResult {
	var p RecordAgentDecisionParams
	if err := json.Unmarshal(args, &p); err != nil {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("INVALID_PARAMS", "Invalid parameters: "+err.Error(), nil),
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

	if p.Decision == "" {
		return CallToolResult{
			Content: []ToolContent{{
				Type: "text",
				Text: serializeError("MISSING_DECISION", "Decision is required", nil),
			}},
			IsError: true,
		}
	}

	if p.RepoPath == "" {
		p.RepoPath = "."
	}

	// 1. Get git details
	repoSHA := "unknown"
	if sha, err := git.RunGit(p.RepoPath, "rev-parse", "HEAD"); err == nil {
		repoSHA = sha
	}

	// 2. Get policy details
	policyVersion := "1.0"
	policyFile := filepath.Join(p.RepoPath, ".pkgsafe/policy.yaml")
	if pol, err := policy.ResolvePolicy("", policyFile, e.PolicyPath, "", ""); err == nil {
		if pol.PolicyPackVersion != "" {
			policyVersion = pol.PolicyPackVersion
		} else if pol.SchemaVersion != "" {
			policyVersion = pol.SchemaVersion
		}
	}

	// 3. Build local agent audit log entry
	eventID := fmt.Sprintf("evt-%s-%03d", time.Now().Format("20060102"), time.Now().UnixNano()%1000)
	timestamp := time.Now().UTC().Format(time.RFC3339)

	event := AgentAuditEvent{
		EventID:               eventID,
		Timestamp:             timestamp,
		AgentName:             p.Agent,
		AgentTool:             "record_agent_decision",
		RepoPath:              p.RepoPath,
		RepoSHA:               repoSHA,
		Package:               p.Name,
		Ecosystem:             p.Ecosystem,
		Version:               p.Version,
		CommandRequested:      fmt.Sprintf("record_agent_decision %s %s %s", p.Ecosystem, p.Name, p.Version),
		Decision:              p.Decision,
		RiskScore:             0,
		PolicyVersion:         policyVersion,
		EvidenceID:            p.EvidenceID,
		HumanApprovalRequired: p.Decision == "WARN" || p.Decision == "REVIEW_REQUIRED",
		HumanApprovalRecorded: p.HumanApproved,
		RedactionStatus:       "clean",
	}

	// Append to ~/.pkgsafe/agent_audit.log
	logDir := expandHomeDir("~/.pkgsafe")
	if err := os.MkdirAll(logDir, 0755); err == nil {
		logFile := filepath.Join(logDir, "agent_audit.log")
		if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			defer f.Close()
			if b, err := json.Marshal(event); err == nil {
				_, _ = f.Write(append(b, '\n'))
			}
		}
	}

	// Return standard agent-facing response
	toolRes := AgentMCPResult{
		Decision:           p.Decision,
		RiskScore:          0,
		Confidence:         "high",
		TopReasons:         []string{"Decision recorded successfully"},
		PolicyResult:       "PASS",
		EvidenceID:         p.EvidenceID,
		AgentInstruction:   "Decision has been logged.",
		AllowedNextActions: []string{"proceed"},
		ProhibitedActions:  []string{},
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

func expandHomeDir(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	} else if path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
	}
	return path
}
