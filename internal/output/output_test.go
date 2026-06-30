package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

func TestJSONOutputIncludesReasonFields(t *testing.T) {
	res := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "npm", Name: "example-package", Version: "1.2.3"},
		Mode:     "warn",
		Score:    62,
		Decision: types.DecisionWarn,
		Thresholds: types.Thresholds{
			AllowMaxScore: 29,
			WarnMaxScore:  69,
			BlockMinScore: 70,
		},
		Reasons: []types.Reason{{
			ID:          "lifecycle_script_present",
			Severity:    "medium",
			ScoreImpact: 20,
			Description: "Package defines a postinstall script",
		}},
		Recommended: "Review package before installing.",
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Ecosystem string `json:"ecosystem"`
		Package   string `json:"package"`
		Version   string `json:"version"`
		Mode      string `json:"mode"`
		Decision  string `json:"decision"`
		RiskScore int    `json:"risk_score"`
		Reasons   []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			Score    int    `json:"score"`
			Message  string `json:"message"`
		} `json:"reasons"`
		Recommended string `json:"recommended_action"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Ecosystem != "npm" || got.Package != "example-package" || got.Version != "1.2.3" || got.Mode != "warn" {
		t.Fatalf("missing package fields: %s", buf.String())
	}
	if got.Decision != "warn" || got.RiskScore != 62 || got.Recommended == "" {
		t.Fatalf("missing decision fields: %s", buf.String())
	}
	if len(got.Reasons) != 1 || got.Reasons[0].RuleID == "" || got.Reasons[0].Severity == "" || got.Reasons[0].Score != 20 || got.Reasons[0].Message == "" {
		t.Fatalf("missing reason fields: %s", buf.String())
	}
}

func TestJSONOutputUsesBehaviorAnalysisContract(t *testing.T) {
	res := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "npm", Name: "safe-example", Version: "1.0.0"},
		Mode:     "warn",
		Decision: types.DecisionAllow,
		Sandbox: types.SandboxSummary{
			Enabled:      false,
			BehaviorMode: types.BehaviorDisabled,
			Isolated:     false,
			NetworkMode:  "disabled",
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, true); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["sandbox"]; ok {
		t.Fatalf("JSON output must not expose sandbox as the primary behavior contract: %s", buf.String())
	}
	var got struct {
		BehaviorAnalysis struct {
			Mode     string `json:"mode"`
			Enabled  bool   `json:"enabled"`
			Executed bool   `json:"executed"`
		} `json:"behavior_analysis"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.BehaviorAnalysis.Mode != "disabled" || got.BehaviorAnalysis.Enabled || got.BehaviorAnalysis.Executed {
		t.Fatalf("default behavior analysis contract is wrong: %s", buf.String())
	}
}

func TestJSONOutputMarksHeuristicAsNonIsolated(t *testing.T) {
	res := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "npm", Name: "heuristic-example", Version: "1.0.0"},
		Mode:     "warn",
		Decision: types.DecisionAllow,
		Sandbox: types.SandboxSummary{
			Enabled:      true,
			Available:    true,
			BehaviorMode: types.BehaviorHeuristic,
			Isolated:     false,
			Runner:       "fake-home-process",
			NetworkMode:  "disabled",
			Warning:      "Heuristic behavior analysis runs lifecycle scripts on the host without OS isolation; it is not a security sandbox. Use only in disposable environments.",
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		BehaviorAnalysis struct {
			Mode        string   `json:"mode"`
			Executed    bool     `json:"executed"`
			Isolated    bool     `json:"isolated"`
			Runner      string   `json:"runner"`
			Warning     string   `json:"warning"`
			Limitations []string `json:"limitations"`
		} `json:"behavior_analysis"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	ba := got.BehaviorAnalysis
	if ba.Mode != "heuristic" || ba.Isolated || ba.Runner != "fake-home-process" {
		t.Fatalf("heuristic behavior analysis metadata is wrong: %s", buf.String())
	}
	if !strings.Contains(ba.Warning, "not a security sandbox") {
		t.Fatalf("heuristic warning must say it is not a security sandbox: %s", buf.String())
	}
	if !containsString(ba.Limitations, "non-isolated host runner") || !containsString(ba.Limitations, "not a security sandbox") {
		t.Fatalf("heuristic limitations missing non-isolated wording: %s", buf.String())
	}
}

func TestJSONOutputShowsBlockDidNotExecuteBehavior(t *testing.T) {
	res := types.ScanResult{
		Package:  types.PackageIdentity{Ecosystem: "npm", Name: "reads-credentials", Version: "1.0.0"},
		Mode:     "warn",
		Decision: types.DecisionBlock,
		Sandbox: types.SandboxSummary{
			Enabled:       true,
			Available:     true,
			BehaviorMode:  types.BehaviorHeuristic,
			Isolated:      false,
			Runner:        "fake-home-process",
			NetworkMode:   "disabled",
			Warning:       "Heuristic behavior analysis runs lifecycle scripts on the host without OS isolation; it is not a security sandbox. Use only in disposable environments.",
			NotPerformed:  true,
			NotPerfReason: "behavior analysis skipped because static analysis already blocked the package",
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		BehaviorAnalysis struct {
			Executed     bool   `json:"executed"`
			NotPerformed bool   `json:"not_performed"`
			Reason       string `json:"reason"`
		} `json:"behavior_analysis"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	ba := got.BehaviorAnalysis
	if ba.Executed || !ba.NotPerformed || !strings.Contains(ba.Reason, "static analysis already blocked") {
		t.Fatalf("BLOCK behavior analysis skip not represented: %s", buf.String())
	}
}

func containsString(in []string, want string) bool {
	for _, got := range in {
		if got == want {
			return true
		}
	}
	return false
}
