//go:build windows
package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func runCommand(ctx context.Context, cmdStr string, dir string, env []string, timeout time.Duration) (int, bool, string, string, error) {
	cmd := exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", cmdStr)
	cmd.Dir = dir
	cmd.Env = env

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	timedOut := false
	exitCode := 0

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			timedOut = true
			exitCode = -1
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return exitCode, timedOut, stdout.String(), stderr.String(), err
}
