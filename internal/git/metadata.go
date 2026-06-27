package git

import (
	"bytes"
	"os/exec"
	"regexp"
	"strings"
)

// Metadata holds git repository details.
type Metadata struct {
	Root      string `json:"root"`
	RemoteURL string `json:"remote_url"`
	Branch    string `json:"branch"`
	Commit    string `json:"commit"`
	Dirty     bool   `json:"dirty"`
	LatestTag string `json:"latest_tag"`
}

var credentialsRegex = regexp.MustCompile(`(https?://)([^@/]+)@`)

// RedactGitURL removes credentials from Git remote URLs.
func RedactGitURL(url string) string {
	if credentialsRegex.MatchString(url) {
		return credentialsRegex.ReplaceAllString(url, "${1}[REDACTED]@")
	}
	return url
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// RunGit exposes git command execution to other packages.
func RunGit(dir string, args ...string) (string, error) {
	return runGit(dir, args...)
}

// DetectMetadata extracts git details from the repository path.
func DetectMetadata(repoPath string) (Metadata, error) {
	var meta Metadata
	meta.Root = "unknown"
	meta.RemoteURL = "unknown"
	meta.Branch = "unknown"
	meta.Commit = "unknown"
	meta.LatestTag = "unknown"

	_, err := runGit(repoPath, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return meta, err
	}

	root, err := runGit(repoPath, "rev-parse", "--show-toplevel")
	if err == nil {
		meta.Root = root
	}

	remote, err := runGit(repoPath, "config", "--get", "remote.origin.url")
	if err == nil {
		meta.RemoteURL = RedactGitURL(remote)
	}

	branch, err := runGit(repoPath, "rev-parse", "--abbrev-ref", "HEAD")
	if err == nil {
		meta.Branch = branch
	}

	commit, err := runGit(repoPath, "rev-parse", "HEAD")
	if err == nil {
		meta.Commit = commit
	}

	status, err := runGit(repoPath, "status", "--porcelain")
	if err == nil {
		meta.Dirty = strings.TrimSpace(status) != ""
	}

	tag, err := runGit(repoPath, "describe", "--tags", "--abbrev=0")
	if err == nil {
		meta.LatestTag = tag
	}

	return meta, nil
}
