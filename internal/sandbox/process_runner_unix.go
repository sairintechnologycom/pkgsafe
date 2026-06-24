//go:build !windows

package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func runCommand(ctx context.Context, cmdStr string, dir string, env []string, timeout time.Duration) (int, bool, string, string, error) {
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Dir = dir
	cmd.Env = env
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
		// Kill the process group
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
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
