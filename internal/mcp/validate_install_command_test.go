package mcp

import (
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestResolveValidateInstallDecisionReviewRequired(t *testing.T) {
	got := resolveValidateInstallDecision(false, false, true)
	if got != types.DecisionReviewRequired {
		t.Fatalf("expected review_required, got %s", got)
	}
}

func TestValidateInstallAllowedReviewRequired(t *testing.T) {
	got := validateInstallAllowed(types.DecisionReviewRequired, policy.ModeWarn, "ai_agent", policy.MCPSettings{})
	if got {
		t.Fatal("expected REVIEW_REQUIRED to disallow install")
	}
}

func TestValidateInstallRecommendedActionReviewRequired(t *testing.T) {
	got := validateInstallRecommendedAction(types.DecisionReviewRequired)
	if got != "Request authorized human review before installing." {
		t.Fatalf("unexpected recommended action: %q", got)
	}
}
