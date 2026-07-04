//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
)

// requireIsolatedRunner returns the platform isolated runner. When
// PKGSAFE_REQUIRE_ISOLATED_E2E=1 (set by the dedicated CI job) an unavailable
// runner fails the test instead of skipping, so CI proves the backend really
// executed and cannot silently skip the whole suite.
func requireIsolatedRunner(t *testing.T) IsolatedRunner {
	t.Helper()
	r := NewIsolatedRunner()
	if !r.Available(context.Background()) {
		reason := r.UnavailableReason(context.Background())
		if os.Getenv("PKGSAFE_REQUIRE_ISOLATED_E2E") == "1" {
			t.Fatalf("isolated runner required by PKGSAFE_REQUIRE_ISOLATED_E2E but unavailable: %s", reason)
		}
		t.Skipf("isolated runner unavailable: %s", reason)
	}
	return r
}

func isolatedRequest(script string, timeout time.Duration) SandboxRequest {
	return SandboxRequest{
		Ecosystem:     "npm",
		PackageName:   "test-pkg",
		Version:       "1.0.0",
		ScriptName:    "postinstall",
		ScriptCommand: script,
		Timeout:       timeout,
		NetworkMode:   "disabled",
		Policy:        policy.Default(),
	}
}

func TestIsolatedNetworkDisabledByDefault(t *testing.T) {
	r := requireIsolatedRunner(t)

	// A live TCP listener on the host loopback: if the sandbox shared the
	// host network namespace, the script's connect would succeed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	connected := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			connected <- struct{}{}
		}
	}()

	script := fmt.Sprintf("bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d'", port)
	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest(script, 10*time.Second))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("TCP connect to host loopback succeeded inside the sandbox; network namespace is NOT isolated")
	}
	select {
	case <-connected:
		t.Fatal("host listener received a connection from the sandboxed script")
	case <-time.After(200 * time.Millisecond):
	}
	if !res.Isolated {
		t.Error("result should be marked isolated")
	}
}

func TestIsolatedNetworkHostModeShares(t *testing.T) {
	r := requireIsolatedRunner(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	connected := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			connected <- struct{}{}
		}
	}()

	req := isolatedRequest(fmt.Sprintf("bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d'", port), 10*time.Second)
	req.NetworkMode = "host"
	res, err := r.RunLifecycleScript(context.Background(), req)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("network_mode=host connect failed, exit=%d", res.ExitCode)
	}
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("host listener never received the connection in network_mode=host")
	}
}

func TestIsolatedHostHomeInvisibleAndIdentity(t *testing.T) {
	r := requireIsolatedRunner(t)

	realHome := os.Getenv("HOME")
	if realHome == "" {
		t.Skip("no HOME set")
	}
	script := fmt.Sprintf(
		`[ ! -e "%s" ] && [ "$HOME" = /home/pkgsafe ] && [ -f "$HOME/.npmrc" ] && [ "$(id -u)" = 65534 ] && [ "$(hostname)" = pkgsafe ]`,
		realHome,
	)
	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest(script, 10*time.Second))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("isolation identity checks failed (exit=%d): host HOME visible, wrong HOME, missing canary, wrong uid, or wrong hostname", res.ExitCode)
	}
}

func TestIsolatedEnvironmentIsCleared(t *testing.T) {
	r := requireIsolatedRunner(t)

	t.Setenv("PKGSAFE_E2E_SENTINEL_SECRET", "leak-me-if-you-can")
	script := `[ -z "$PKGSAFE_E2E_SENTINEL_SECRET" ]`
	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest(script, 10*time.Second))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatal("host environment variable leaked into the sandbox")
	}
}

func TestIsolatedTeardownIsCleanEvenWhenHostile(t *testing.T) {
	r := requireIsolatedRunner(t)

	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	// The script tries to make teardown fail by dropping permissions on a
	// directory it created.
	script := `mkdir -p /workspace/locked && touch /workspace/locked/f && chmod 000 /workspace/locked`
	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest(script, 10*time.Second))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("setup script failed, exit=%d", res.ExitCode)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("teardown left %s behind", filepath.Join(tmp, e.Name()))
	}
}

func TestIsolatedNonzeroExitAndTimeoutAreNotErrors(t *testing.T) {
	r := requireIsolatedRunner(t)

	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest("exit 3", 10*time.Second))
	if err != nil {
		t.Fatalf("non-zero script exit must not be an infrastructure error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("expected exit code 3, got %d", res.ExitCode)
	}

	res, err = r.RunLifecycleScript(context.Background(), isolatedRequest("sleep 30", 1*time.Second))
	if err != nil {
		t.Fatalf("timeout must not be an infrastructure error: %v", err)
	}
	if !res.TimedOut {
		t.Error("expected TimedOut=true")
	}
}

func TestIsolatedCanaryFindingEndToEnd(t *testing.T) {
	r := requireIsolatedRunner(t)

	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest("cat $HOME/.npmrc", 10*time.Second))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("canary read failed, exit=%d — private HOME not mounted correctly", res.ExitCode)
	}
	found := false
	for _, f := range res.Findings {
		if f.RuleID == "credential_canary_read" {
			found = true
		}
	}
	if !found {
		t.Error("expected credential_canary_read finding from isolated run")
	}
}

func TestIsolatedTraceReportsNetworkState(t *testing.T) {
	r := requireIsolatedRunner(t)

	res, err := r.RunLifecycleScript(context.Background(), isolatedRequest("true", 10*time.Second))
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if res.Runner != "bubblewrap-linux" {
		t.Errorf("unexpected runner %q", res.Runner)
	}
	hasNet := false
	for _, line := range res.Trace {
		if line == "network namespace unshared; network access disabled" {
			hasNet = true
		}
	}
	if !hasNet {
		t.Errorf("trace missing network-disabled line: %v", res.Trace)
	}
}
