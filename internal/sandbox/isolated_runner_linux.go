//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type bubblewrapRunner struct{}

func newPlatformIsolatedRunner() IsolatedRunner {
	return &bubblewrapRunner{}
}

func (r *bubblewrapRunner) Name() string {
	return "bubblewrap-linux"
}

func (r *bubblewrapRunner) Available(ctx context.Context) bool {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, path, "--unshare-user", "--uid", "65534", "--gid", "65534", "true")
	return cmd.Run() == nil
}

func (r *bubblewrapRunner) UnavailableReason(ctx context.Context) string {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return "isolated behavior analysis requires bubblewrap (bwrap) on Linux"
	}
	return "bubblewrap is installed but user namespace isolation is unavailable on this host"
}

func (r *bubblewrapRunner) RunLifecycleScript(ctx context.Context, req SandboxRequest) (*SandboxResult, error) {
	if !r.Available(ctx) {
		return nil, errors.New(r.UnavailableReason(ctx))
	}
	sandboxRoot, workspaceDir, cleanup, err := prepareWorkspace(req)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	beforeFileInfo := RecordFileInfo(sandboxRoot)
	timeout := req.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	exitCode, timedOut, stdout, stderr, err := runBubblewrapCommand(runCtx, req, sandboxRoot, workspaceDir)
	duration := time.Since(start)
	findings := AnalyzeBehavior(req, sandboxRoot, beforeFileInfo, exitCode, timedOut, stdout, stderr)

	return &SandboxResult{
		ScriptName: req.ScriptName,
		ExitCode:   exitCode,
		TimedOut:   timedOut,
		DurationMs: duration.Milliseconds(),
		Runner:     r.Name(),
		Isolated:   true,
		Trace: []string{
			"created disposable workspace",
			"created private HOME with credential canaries",
			"executed inside bubblewrap user/mount/pid/ipc/uts namespace",
			"network namespace unshared; network disabled by default",
			"host HOME and common credential directories are not mounted",
			"temporary workspace removed after execution",
		},
		Findings: findings,
	}, err
}

func runBubblewrapCommand(ctx context.Context, req SandboxRequest, sandboxRoot, workspaceDir string) (int, bool, string, string, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return -1, false, "", "", err
	}

	args := []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup",
		"--die-with-parent",
		"--new-session",
		"--uid", "65534",
		"--gid", "65534",
		"--clearenv",
		"--setenv", "HOME", "/home/pkgsafe",
		"--setenv", "USERPROFILE", "/home/pkgsafe",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "TEMP", "/tmp",
		"--setenv", "TMP", "/tmp",
		"--setenv", "XDG_CONFIG_HOME", "/home/pkgsafe/.config",
		"--setenv", "XDG_CACHE_HOME", "/home/pkgsafe/.cache",
		"--setenv", "XDG_DATA_HOME", "/home/pkgsafe/.local/share",
		"--setenv", "PATH", safePath(),
		"--dir", "/tmp",
		"--dir", "/run",
		"--proc", "/proc",
		"--dev", "/dev",
		"--bind", filepath.Join(sandboxRoot, "home"), "/home/pkgsafe",
		"--bind", workspaceDir, "/workspace",
		"--chdir", "/workspace",
		"--rlimit-nofile", "64",
	}
	if req.NetworkMode == "host" {
		args = append(args, "--share-net")
	} else {
		args = append(args, "--unshare-net")
	}
	for _, path := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc/alternatives"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	args = append(args, "sh", "-c", req.ScriptCommand)

	cmd := exec.CommandContext(ctx, bwrapPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return -1, false, "", "", err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = cmd.Process.Kill()
		}
		<-done
		return -1, true, stdout.String(), stderr.String(), context.DeadlineExceeded
	case err := <-done:
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		return exitCode, false, stdout.String(), stderr.String(), err
	}
}

func safePath() string {
	if path := os.Getenv("PATH"); path != "" {
		return path
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}
