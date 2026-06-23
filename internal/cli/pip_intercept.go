package cli

import (
	"context"

	"github.com/niyam-ai/pkgsafe/internal/intercept"
)

func PipIntercept(args []string) error {
	ctx := context.Background()
	executor := intercept.DefaultExecutor{}
	return intercept.RunIntercept(ctx, "pip", args, executor)
}

func PythonIntercept(args []string) error {
	ctx := context.Background()
	executor := intercept.DefaultExecutor{}
	return intercept.RunIntercept(ctx, "python", args, executor)
}
