package cli

import (
	"context"
	"fmt"

	"github.com/niyam-ai/pkgsafe/internal/intercept"
)

func RunIntercept(args []string) error {
	if len(args) == 0 {
		return intercept.InterceptError{Code: intercept.ExitUsageError, Err: fmt.Errorf("usage: pkgsafe run [--] <command> [args...]")}
	}
	if args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return intercept.InterceptError{Code: intercept.ExitUsageError, Err: fmt.Errorf("usage: pkgsafe run [--] <command> [args...]")}
	}

	pm := args[0]
	pmArgs := args[1:]

	ctx := context.Background()
	executor := intercept.DefaultExecutor{}
	return intercept.RunIntercept(ctx, pm, pmArgs, executor)
}
