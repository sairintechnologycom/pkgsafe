package intercept

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/niyam-ai/pkgsafe/internal/policy"
)

type PackageManagerExecutor interface {
	Resolve(pm string, pol policy.Policy) (string, error)
	Execute(ctx context.Context, binary string, args []string, env []string, cwd string) (int, error)
}

type DefaultExecutor struct{}

func (e DefaultExecutor) Resolve(pm string, pol policy.Policy) (string, error) {
	// 1. Check if policy specifies a real_binary path
	var configPath string
	switch pm {
	case "npm":
		configPath = pol.PackageManagers.NPM.RealBinary
	case "pip", "python-pip":
		configPath = pol.PackageManagers.Pip.RealBinary
	}

	if configPath != "" {
		absPath := expandHome(configPath)
		if fi, err := os.Stat(absPath); err == nil && !fi.IsDir() {
			return absPath, nil
		}
		return "", fmt.Errorf("configured real_binary for %s not found: %s", pm, configPath)
	}

	// 2. Resolve target binary name
	binaryName := pm
	if pm == "python-pip" {
		binaryName = "python"
	}

	// 3. Look up in PATH while avoiding self-recursion
	realPath, err := LookPathReal(binaryName)
	if err != nil {
		return "", fmt.Errorf("could not find real binary for %s: %w", binaryName, err)
	}
	return realPath, nil
}

func (e DefaultExecutor) Execute(ctx context.Context, binary string, args []string, env []string, cwd string) (int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = cwd
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Prepare environment
	var cmdEnv []string
	if len(env) > 0 {
		cmdEnv = append(cmdEnv, env...)
	} else {
		cmdEnv = append(cmdEnv, os.Environ()...)
	}

	// Append active flag to prevent recursion
	cmdEnv = append(cmdEnv, "PKGSAFE_INTERCEPT_ACTIVE=1")
	cmd.Env = cmdEnv

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return ExitInstallFailed, err
	}

	return ExitSuccess, nil
}

func LookPathReal(binary string) (string, error) {
	currentExe, err := os.Executable()
	if err != nil {
		currentExe = ""
	}
	currentExeAbs, _ := filepath.Abs(currentExe)

	pathVal := os.Getenv("PATH")
	paths := filepath.SplitList(pathVal)
	for _, dir := range paths {
		if dir == "" {
			dir = "."
		}
		path := filepath.Join(dir, binary)
		fi, err := os.Stat(path)
		if err == nil && !fi.IsDir() && isExecutable(fi) {
			absPath, err := filepath.Abs(path)
			if err == nil {
				if absPath == currentExeAbs {
					continue // Skip ourselves
				}
				evalPath, err := filepath.EvalSymlinks(absPath)
				if err == nil && evalPath == currentExeAbs {
					continue // Skip symlinks to ourselves
				}
			}
			return path, nil
		}
	}

	// Fallback to standard LookPath
	return exec.LookPath(binary)
}

func isExecutable(fi os.FileInfo) bool {
	return fi.Mode()&0111 != 0
}
