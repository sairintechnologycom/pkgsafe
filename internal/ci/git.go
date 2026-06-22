package ci

import (
	"bytes"
	"os/exec"
	"strings"
)

// IsGitRepo checks if the current working directory is inside a Git repository.
func IsGitRepo(cwd string) bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = cwd
	err := cmd.Run()
	return err == nil
}

// GetGitRoot returns the absolute path to the root of the Git repository.
func GetGitRoot(cwd string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = cwd
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// GetFileFromBranch retrieves the content of a file at a specific branch/commit.
func GetFileFromBranch(cwd, branch, relPath string) ([]byte, error) {
	cmd := exec.Command("git", "show", branch+":"+relPath)
	cmd.Dir = cwd
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
