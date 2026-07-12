package sandbox

import (
	"context"
	"fmt"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// ValidateOfflineBehavior enforces the product meaning of offline before any
// package acquisition or lifecycle runner selection occurs.
func ValidateOfflineBehavior(ctx context.Context, mode types.BehaviorMode, networkMode string) error {
	switch mode {
	case "", types.BehaviorDisabled:
		return nil
	case types.BehaviorHeuristic:
		return fmt.Errorf("offline mode forbids heuristic behavior analysis because host execution cannot enforce network isolation")
	case types.BehaviorIsolated:
		if networkMode != "" && networkMode != "disabled" {
			return fmt.Errorf("offline isolated behavior analysis requires network_mode=disabled")
		}
		runner := NewIsolatedRunner()
		if !runner.Available(ctx) {
			return fmt.Errorf("offline isolated behavior analysis unavailable: %s", runner.UnavailableReason(ctx))
		}
		return nil
	default:
		return fmt.Errorf("unsupported behavior analysis mode %q", mode)
	}
}
