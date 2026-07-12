package sandbox

import (
	"context"
	"strings"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func TestOfflineBehaviorValidation(t *testing.T) {
	if err := ValidateOfflineBehavior(context.Background(), types.BehaviorDisabled, "disabled"); err != nil {
		t.Fatalf("disabled behavior must be allowed offline: %v", err)
	}
	if err := ValidateOfflineBehavior(context.Background(), types.BehaviorHeuristic, "disabled"); err == nil || !strings.Contains(err.Error(), "forbids heuristic") {
		t.Fatalf("offline heuristic must fail before runner selection, got %v", err)
	}
	if err := ValidateOfflineBehavior(context.Background(), types.BehaviorIsolated, "host"); err == nil || !strings.Contains(err.Error(), "network_mode=disabled") {
		t.Fatalf("offline isolated host networking must fail, got %v", err)
	}
}
