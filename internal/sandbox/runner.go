package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// SandboxRunner performs heuristic behavior analysis of package lifecycle
// scripts. NOTE: despite the name, the current ProcessRunner does NOT provide
// OS-level isolation — scripts execute on the host as the current user with
// only a redirected fake HOME and a cleaned environment. It observes behavior
// (file/network/process heuristics); it does not contain it.
type SandboxRunner interface {
	Available(ctx context.Context) bool
	RunLifecycleScript(ctx context.Context, req SandboxRequest) (*SandboxResult, error)
}

type RunnerMetadata struct {
	Name        string
	Isolated    bool
	Available   bool
	Unavailable string
	Warning     string
}

type RunnerSelection struct {
	Runner SandboxRunner
	Meta   RunnerMetadata
}

type IsolatedRunner interface {
	SandboxRunner
	Name() string
	UnavailableReason(ctx context.Context) string
}

type ProcessRunner struct{}

func SelectRunner(ctx context.Context, mode types.BehaviorMode) RunnerSelection {
	switch mode {
	case types.BehaviorHeuristic:
		runner := &ProcessRunner{}
		available := runner.Available(ctx)
		meta := RunnerMetadata{
			Name:      "fake-home-process",
			Isolated:  false,
			Available: available,
			Warning:   "Heuristic behavior analysis runs lifecycle scripts on the host without OS isolation; it is not a security sandbox. Use only in disposable environments.",
		}
		if !available {
			meta.Unavailable = "No supported heuristic behavior-analysis runner available on this platform"
		}
		return RunnerSelection{Runner: runner, Meta: meta}
	case types.BehaviorIsolated:
		runner := NewIsolatedRunner()
		available := runner.Available(ctx)
		meta := RunnerMetadata{
			Name:      runner.Name(),
			Isolated:  true,
			Available: available,
			Warning:   "Isolated mode executes lifecycle scripts inside Linux user/mount/pid/ipc/uts/network namespaces (bubblewrap) with networking disabled by default. It reduces host exposure but shares the host kernel; it is not a hypervisor boundary.",
		}
		if !available {
			meta.Unavailable = runner.UnavailableReason(ctx)
		}
		return RunnerSelection{Runner: runner, Meta: meta}
	default:
		return RunnerSelection{Meta: RunnerMetadata{Name: "none"}}
	}
}

func NewIsolatedRunner() IsolatedRunner {
	return newPlatformIsolatedRunner()
}

func IsAvailable(ctx context.Context) bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

func (pr *ProcessRunner) Available(ctx context.Context) bool {
	return IsAvailable(ctx)
}

func prepareWorkspace(req SandboxRequest) (sandboxRoot, workspaceDir string, cleanup func(), err error) {
	sandboxRoot, err = os.MkdirTemp("", "pkgsafe-sandbox-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("create sandbox temp dir: %w", err)
	}
	cleanup = func() {
		if !req.KeepSandbox {
			if err := removeAllForce(sandboxRoot); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: sandbox teardown left files behind at %s: %v\n", sandboxRoot, err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Keeping sandbox directory at: %s\n", sandboxRoot)
		}
	}

	if err := CreateFakeHome(sandboxRoot); err != nil {
		cleanup()
		return "", "", nil, fmt.Errorf("create fake home: %w", err)
	}

	workspaceDir = filepath.Join(sandboxRoot, "workspace")
	if req.PackagePath != "" {
		if err := CopyDir(req.PackagePath, workspaceDir); err != nil {
			cleanup()
			return "", "", nil, fmt.Errorf("copy package files: %w", err)
		}
	}
	return sandboxRoot, workspaceDir, cleanup, nil
}

// removeAllForce removes root even when a lifecycle script stripped
// permissions from files or directories it created (for example
// `chmod 000` on a workspace subdirectory), so teardown never leaks
// sandbox contents onto the host.
func removeAllForce(root string) error {
	err := os.RemoveAll(root)
	if err == nil {
		return nil
	}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			_ = os.Chmod(path, 0700)
		} else {
			_ = os.Chmod(path, 0600)
		}
		return nil
	})
	return os.RemoveAll(root)
}

func (pr *ProcessRunner) RunLifecycleScript(ctx context.Context, req SandboxRequest) (*SandboxResult, error) {
	sandboxRoot, workspaceDir, cleanup, err := prepareWorkspace(req)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	beforeFileInfo := RecordFileInfo(sandboxRoot)
	env := CleanEnv(sandboxRoot)

	// Be explicit and honest: this runner does NOT isolate. Lifecycle scripts
	// execute on the host as the current user. The only mitigations are a
	// redirected fake HOME and a cleaned environment; the real filesystem,
	// network, and processes are fully reachable. This is heuristic behavior
	// analysis, not a security sandbox — never rely on it to contain malicious
	// code; run it only in a disposable environment.
	fmt.Fprintln(os.Stderr, "WARNING: lifecycle scripts run on the host WITHOUT isolation (no container, namespace, or network sandbox). This is heuristic behavior analysis, not containment.")
	if req.NetworkMode == "disabled" {
		fmt.Fprintln(os.Stderr, "WARNING: network_mode=disabled is NOT enforced by this runner; network access is not actually blocked.")
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
		Runner:     "fake-home-process",
		Isolated:   false,
		Trace: []string{
			"created disposable workspace",
			"redirected HOME to fake credential canaries",
			"executed lifecycle script on host without OS isolation",
		},
		Findings: findings,
	}

	return res, nil
}
