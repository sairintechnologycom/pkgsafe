package cli

import (
	"context"

	"github.com/niyam-ai/pkgsafe/internal/intercept"
)

func NPMIntercept(args []string) error {
	ctx := context.Background()
	executor := intercept.DefaultExecutor{}
	return intercept.RunIntercept(ctx, "npm", args, executor)
}
