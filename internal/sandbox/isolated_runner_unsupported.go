//go:build !linux

package sandbox

import (
	"context"
	"errors"
)

type unsupportedIsolatedRunner struct{}

func newPlatformIsolatedRunner() IsolatedRunner {
	return &unsupportedIsolatedRunner{}
}

func (r *unsupportedIsolatedRunner) Name() string {
	return "isolated-unavailable"
}

func (r *unsupportedIsolatedRunner) Available(ctx context.Context) bool {
	return false
}

func (r *unsupportedIsolatedRunner) UnavailableReason(ctx context.Context) string {
	return "isolated behavior analysis is currently supported only on Linux hosts with bubblewrap"
}

func (r *unsupportedIsolatedRunner) RunLifecycleScript(ctx context.Context, req SandboxRequest) (*SandboxResult, error) {
	return nil, errors.New(r.UnavailableReason(ctx))
}
