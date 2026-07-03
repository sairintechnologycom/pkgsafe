//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// sandboxPATH is the PATH exposed inside the sandbox. It is a fixed value:
// the host PATH may reference user-specific directories that do not exist
// inside the sandbox and would leak host filesystem layout to the script.
const sandboxPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// systemReadOnlyBinds are host directories bind-mounted read-only so that
// shells and interpreters are executable inside the sandbox. Only paths that
// exist on the host are mounted.
var systemReadOnlyBinds = []string{"/usr", "/bin", "/lib", "/lib64", "/etc/alternatives"}

// hostNetworkReadOnlyBinds are additionally mounted read-only when
// network_mode=host so that DNS resolution and TLS verification work.
var hostNetworkReadOnlyBinds = []string{
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/ca-certificates.conf",
}

type bubblewrapRunner struct{}

func newPlatformIsolatedRunner() IsolatedRunner {
	return &bubblewrapRunner{}
}

func (r *bubblewrapRunner) Name() string {
	return "bubblewrap-linux"
}

// namespaceArgs is the namespace/lifecycle flag set shared by the
// availability probe and real runs, so that Available() cannot report true
// for a configuration RunLifecycleScript would fail on.
func namespaceArgs(shareNetwork bool) []string {
	args := []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--die-with-parent",
		"--new-session",
		"--uid", "65534",
		"--gid", "65534",
		"--hostname", "pkgsafe",
	}
	if shareNetwork {
		args = append(args, "--share-net")
	} else {
		args = append(args, "--unshare-net")
	}
	return args
}

func roBindArgs(paths []string) []string {
	var args []string
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	return args
}

func (r *bubblewrapRunner) Available(ctx context.Context) bool {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	args := namespaceArgs(false)
	args = append(args, "--clearenv", "--setenv", "PATH", sandboxPATH)
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp")
	args = append(args, roBindArgs(systemReadOnlyBinds)...)
	args = append(args, "true")
	cmd := exec.CommandContext(probeCtx, path, args...)
	return cmd.Run() == nil
}

func (r *bubblewrapRunner) UnavailableReason(ctx context.Context) string {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return "isolated behavior analysis requires bubblewrap (bwrap) on Linux"
	}
	return "bubblewrap is installed but user namespace isolation is unavailable on this host (unprivileged user namespaces may be restricted)"
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

	shareNetwork := req.NetworkMode == "host"

	start := time.Now()
	exitCode, timedOut, stdout, stderr, err := runBubblewrapCommand(runCtx, req, sandboxRoot, workspaceDir, shareNetwork)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("isolated behavior analysis failed to execute: %w", err)
	}
	findings := AnalyzeBehavior(req, sandboxRoot, beforeFileInfo, exitCode, timedOut, stdout, stderr)

	trace := []string{
		"created disposable workspace",
		"created private HOME with credential canaries",
		"executed inside bubblewrap user/mount/pid/ipc/uts namespace as uid 65534",
		"host HOME and common credential directories are not mounted",
	}
	if shareNetwork {
		trace = append(trace, "host network shared (network_mode=host)")
	} else {
		trace = append(trace, "network namespace unshared; network access disabled")
		if req.NetworkMode != "" && req.NetworkMode != "disabled" {
			trace = append(trace, fmt.Sprintf("network_mode=%s is not supported by the isolated backend; network disabled (fail closed)", req.NetworkMode))
		}
	}
	if req.KeepSandbox {
		trace = append(trace, "sandbox directory kept for inspection (--keep-sandbox)")
	} else {
		trace = append(trace, "temporary workspace removed after execution")
	}

	return &SandboxResult{
		ScriptName: req.ScriptName,
		ExitCode:   exitCode,
		TimedOut:   timedOut,
		DurationMs: duration.Milliseconds(),
		Runner:     r.Name(),
		Isolated:   true,
		Trace:      trace,
		Findings:   findings,
	}, nil
}

// syntheticEtcFiles writes minimal /etc/passwd and /etc/group files into the
// sandbox root so tools that resolve the current user (whoami, id, npm) see a
// consistent nobody identity instead of the host account database.
func syntheticEtcFiles(sandboxRoot string) (passwdPath, groupPath string, err error) {
	etcDir := filepath.Join(sandboxRoot, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		return "", "", err
	}
	passwdPath = filepath.Join(etcDir, "passwd")
	groupPath = filepath.Join(etcDir, "group")
	passwd := "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/home/pkgsafe:/bin/sh\n"
	group := "root:x:0:\nnogroup:x:65534:\n"
	if err := os.WriteFile(passwdPath, []byte(passwd), 0644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(groupPath, []byte(group), 0644); err != nil {
		return "", "", err
	}
	return passwdPath, groupPath, nil
}

// resourceLimitPrefix caps file descriptors, process count, and file size via
// shell ulimit builtins. bubblewrap has no rlimit options, so limits are set
// inside the sandboxed shell; each is guarded because shells differ in which
// flags they support, and a failed ulimit must not abort the script.
func resourceLimitPrefix() string {
	return "ulimit -n 256 2>/dev/null; ulimit -u 256 2>/dev/null; ulimit -p 256 2>/dev/null; ulimit -f 1048576 2>/dev/null; "
}

func runBubblewrapCommand(ctx context.Context, req SandboxRequest, sandboxRoot, workspaceDir string, shareNetwork bool) (int, bool, string, string, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return -1, false, "", "", err
	}

	passwdPath, groupPath, err := syntheticEtcFiles(sandboxRoot)
	if err != nil {
		return -1, false, "", "", fmt.Errorf("create synthetic /etc files: %w", err)
	}

	args := namespaceArgs(shareNetwork)
	args = append(args,
		"--clearenv",
		"--setenv", "HOME", "/home/pkgsafe",
		"--setenv", "USERPROFILE", "/home/pkgsafe",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "TEMP", "/tmp",
		"--setenv", "TMP", "/tmp",
		"--setenv", "XDG_CONFIG_HOME", "/home/pkgsafe/.config",
		"--setenv", "XDG_CACHE_HOME", "/home/pkgsafe/.cache",
		"--setenv", "XDG_DATA_HOME", "/home/pkgsafe/.local/share",
		"--setenv", "PATH", sandboxPATH,
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--proc", "/proc",
		"--dev", "/dev",
		"--bind", filepath.Join(sandboxRoot, "home"), "/home/pkgsafe",
		"--bind", workspaceDir, "/workspace",
		"--ro-bind", passwdPath, "/etc/passwd",
		"--ro-bind", groupPath, "/etc/group",
		"--chdir", "/workspace",
	)
	args = append(args, roBindArgs(systemReadOnlyBinds)...)
	if shareNetwork {
		args = append(args, roBindArgs(hostNetworkReadOnlyBinds)...)
	}
	args = append(args, "sh", "-c", resourceLimitPrefix()+req.ScriptCommand)

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
		// A timeout is an observed behavior, not an infrastructure failure;
		// it is reported via TimedOut so results are never silently dropped.
		return -1, true, stdout.String(), stderr.String(), nil
	case err := <-done:
		exitCode := 0
		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				return -1, false, stdout.String(), stderr.String(), err
			}
			// A non-zero script exit is an observed behavior, not an
			// infrastructure failure.
			exitCode = exitErr.ExitCode()
		}
		return exitCode, false, stdout.String(), stderr.String(), nil
	}
}
