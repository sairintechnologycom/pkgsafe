package cli

import (
	"context"

	"github.com/sairintechnologycom/pkgsafe/internal/intercept"
)

func PnpmIntercept(args []string) error {
	ctx := context.Background()
	return intercept.RunIntercept(ctx, "pnpm", args, intercept.DefaultExecutor{})
}

func YarnIntercept(args []string) error {
	ctx := context.Background()
	return intercept.RunIntercept(ctx, "yarn", args, intercept.DefaultExecutor{})
}

func UVIntercept(args []string) error {
	ctx := context.Background()
	return intercept.RunIntercept(ctx, "uv", args, intercept.DefaultExecutor{})
}
