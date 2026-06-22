package output

import (
	"bytes"
	"encoding/json"
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
