package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type SandboxRunner interface {
	Available(ctx context.Context) bool
	RunLifecycleScript(ctx context.Context, req SandboxRequest) (*SandboxResult, error)
}

type ProcessRunner struct{}

func IsAvailable(ctx context.Context) bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

func (pr *ProcessRunner) Available(ctx context.Context) bool {
	return IsAvailable(ctx)
}

func (pr *ProcessRunner) RunLifecycleScript(ctx context.Context, req SandboxRequest) (*SandboxResult, error) {
	sandboxRoot, err := os.MkdirTemp("", "pkgsafe-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("create sandbox temp dir: %w", err)
	}
	if !req.KeepSandbox {
		defer os.RemoveAll(sandboxRoot)
	} else {
		fmt.Fprintf(os.Stderr, "Keeping sandbox directory at: %s\n", sandboxRoot)
	}

	if err := CreateFakeHome(sandboxRoot); err != nil {
		return nil, fmt.Errorf("create fake home: %w", err)
	}

	workspaceDir := filepath.Join(sandboxRoot, "workspace")
	if req.PackagePath != "" {
		if err := CopyDir(req.PackagePath, workspaceDir); err != nil {
			return nil, fmt.Errorf("copy package files: %w", err)
		}
	}

	beforeFileInfo := RecordFileInfo(sandboxRoot)
	env := CleanEnv(sandboxRoot)

	fmt.Fprintln(os.Stderr, "Sandbox isolation is best-effort for this runner.")
	if req.NetworkMode == "disabled" {
		fmt.Fprintln(os.Stderr, "Warning: Network isolation is best-effort for runner fake-home-process.")
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	exitCode, timedOut, stdout, stderr, _ := runCommand(runCtx, req.ScriptCommand, workspaceDir, env, timeout)
	duration := time.Since(start)

	findings := AnalyzeBehavior(req, sandboxRoot, beforeFileInfo, exitCode, timedOut, stdout, stderr)

	res := &SandboxResult{
		ScriptName: req.ScriptName,
		ExitCode:   exitCode,
		TimedOut:   timedOut,
		DurationMs: duration.Milliseconds(),
		Findings:   findings,
	}

	return res, nil
}
