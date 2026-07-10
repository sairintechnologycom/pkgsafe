package cargo

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// maxFiles and maxBytes are artifact budget limits.
// Crates that exceed these limits fail closed (unscannable) rather than silently
// passing. These are package-level vars so tests can override them.
var (
	maxFiles = 10_000
	maxBytes = int64(512 * 1024 * 1024) // 512 MiB
)

var (
	// base64Regex matches long base64-encoded strings embedded in Rust source.
	base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	// hexBlobRegex matches long lowercase or uppercase hex strings.
	hexBlobRegex = regexp.MustCompile(`[0-9a-fA-F]{48,}`)
)

// credentialPaths are protected paths that should never be read by a crate.
var credentialPaths = []string{
	".aws/credentials", ".aws/config",
	".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
	".npmrc", ".pypirc", ".kube/config",
	".azure/", ".gcp/",
	".vault-token",
	".env",
}

// cloudMetadataEndpoints are IMDS URLs used for credential exfiltration.
var cloudMetadataEndpoints = []string{
	"169.254.169.254",       // AWS/GCP/Azure IMDS
	"metadata.google.internal",
	"metadata/instance",
	"latest/meta-data",
}

// secretKeywords are environment-variable names that indicate credential access.
var secretKeywords = []string{
	"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
	"github_token", "gitlab_token", "npm_token",
	"vault_token", "vault_addr",
	"database_url", "db_password",
}

type Analysis struct {
	Result   types.ScanResult
	Findings []types.Reason
}

// AnalyzeDir walks an extracted crate directory and inspects Rust source files
// and Cargo.toml for malicious patterns. Returns an Analysis with all findings.
func AnalyzeDir(dir string, name, version string, pol policy.Policy) (Analysis, error) {
	pkg := types.PackageIdentity{Ecosystem: "cargo", Name: name, Version: version}
	var findings []types.Reason
	var suspicious []string

	var fileCount int
	var totalBytes int64

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		fileCount++
		if fileCount > maxFiles {
			findings = risk.AddReason(findings, "artifact_oversized",
				fmt.Sprintf("Crate exceeds file budget (%d files); artifact not fully scanned", maxFiles), "file_count")
			return filepath.SkipAll
		}

		info, err := d.Info()
		if err == nil {
			totalBytes += info.Size()
		}
		if totalBytes > maxBytes {
			findings = risk.AddReason(findings, "artifact_oversized",
				fmt.Sprintf("Crate exceeds size budget (%d MiB); artifact not fully scanned", maxBytes/(1024*1024)), "size")
			return filepath.SkipAll
		}

		rel, _ := filepath.Rel(dir, path)
		base := filepath.Base(path)
		lowerBase := strings.ToLower(base)

		switch {
		case base == "Cargo.toml":
			f, sf := analyzeCargoToml(path, rel)
			findings = append(findings, f...)
			suspicious = append(suspicious, sf...)

		case base == "build.rs":
			f, sf := analyzeRustSource(path, rel, true)
			findings = append(findings, f...)
			suspicious = append(suspicious, sf...)

		case strings.HasSuffix(lowerBase, ".rs"):
			f, sf := analyzeRustSource(path, rel, false)
			findings = append(findings, f...)
			suspicious = append(suspicious, sf...)
		}

		return nil
	})

	res := risk.Evaluate(pkg, dedupeReasons(findings), nil, unique(suspicious), nil, pol)
	return Analysis{Result: res, Findings: findings}, err
}

// analyzeCargoToml scans a Cargo.toml for suspicious build-dependencies and
// direct-URL source references (which bypass crates.io integrity checks).
func analyzeCargoToml(path, rel string) ([]types.Reason, []string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	content := string(b)
	lower := strings.ToLower(content)

	var findings []types.Reason
	var suspicious []string

	// Direct git/path dependencies bypass crates.io and its security checks.
	if strings.Contains(lower, "git = \"") || strings.Contains(lower, "git=\"") {
		findings = risk.AddReason(findings, "direct_url_dependency",
			"Cargo.toml declares a git-source dependency that bypasses crates.io", rel)
		suspicious = append(suspicious, "git-dependency")
	}
	if strings.Contains(lower, "path = \"") || strings.Contains(lower, "path=\"") {
		// path deps are common in workspaces — flag only if this isn't the root.
		if !strings.Contains(lower, "[workspace]") {
			findings = risk.AddReason(findings, "direct_url_dependency",
				"Cargo.toml declares a path-source dependency that bypasses the registry", rel)
			suspicious = append(suspicious, "path-dependency")
		}
	}

	// Suspicious build-dependencies — network clients or system introspection in build scripts.
	for _, dep := range []string{"reqwest", "ureq", "hyper", "attohttpc", "minreq"} {
		if strings.Contains(lower, dep) && strings.Contains(lower, "[build-dependencies]") {
			findings = risk.AddReason(findings, "suspicious_build_dependency",
				fmt.Sprintf("Cargo.toml declares HTTP client '%s' as a build dependency (build.rs can make network calls)", dep), rel)
			suspicious = append(suspicious, "build-dep:"+dep)
		}
	}

	return findings, suspicious
}

// analyzeRustSource inspects a .rs file for dangerous patterns.
// isBuildScript=true applies stricter rules for build.rs files.
func analyzeRustSource(path, rel string, isBuildScript bool) ([]types.Reason, []string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	content := string(b)
	lower := strings.ToLower(content)

	var findings []types.Reason
	var suspicious []string

	add := func(id, description, evidence string) {
		findings = risk.AddReason(findings, id, description, rel+": "+evidence)
		suspicious = append(suspicious, evidence)
	}

	// 1. Process / shell execution (most dangerous in build.rs)
	if strings.Contains(content, "Command::new") || strings.Contains(content, "std::process::Command") {
		label := "Rust source"
		if isBuildScript {
			label = "build.rs"
		}
		add("shell_execution_in_build",
			fmt.Sprintf("%s spawns child processes via Command::new", label), "Command::new")
	}

	// 2. Network calls
	for _, pat := range []string{
		"TcpStream::connect", "UdpSocket::bind", "TcpListener::bind",
		"reqwest::", "ureq::", "hyper::", "attohttpc::", "minreq::",
		"http::Client", "HttpClient",
	} {
		if strings.Contains(content, pat) {
			add("network_command_in_lifecycle",
				fmt.Sprintf("Rust source performs network operations (%s)", pat), pat)
			break
		}
	}

	// 3. Credential path references
	for _, p := range credentialPaths {
		if strings.Contains(lower, p) {
			add("credential_path_reference",
				fmt.Sprintf("Rust source references protected credential path: %s", p), p)
		}
	}

	// 4. Cloud metadata endpoint access
	for _, ep := range cloudMetadataEndpoints {
		if strings.Contains(lower, ep) {
			add("cloud_metadata_access",
				fmt.Sprintf("Rust source references cloud instance metadata endpoint: %s", ep), ep)
		}
	}

	// 5. Environment variable exfiltration (env var access + network in same file)
	envAccess := strings.Contains(content, "std::env::var") ||
		strings.Contains(content, "env::var(") ||
		strings.Contains(content, "std::env::vars()")
	netAccess := strings.Contains(content, "TcpStream") ||
		strings.Contains(content, "reqwest") ||
		strings.Contains(content, "ureq") ||
		strings.Contains(content, "http::")
	if envAccess && netAccess {
		add("env_secret_exfil",
			"Rust source reads environment variables and performs network calls (possible secret exfiltration)", "env+network")
	}

	// 6. Secret keyword references
	for _, k := range secretKeywords {
		if strings.Contains(lower, k) {
			add("secret_keyword_reference",
				fmt.Sprintf("Rust source references secret-related keyword: %s", k), k)
			break
		}
	}

	// 7. Encoded payloads — base64 blobs or hex blobs embedded in source
	if base64Regex.MatchString(content) && (strings.Contains(lower, "decode") || strings.Contains(lower, "from_utf8") || strings.Contains(lower, "exec")) {
		add("encoded_payload",
			"Rust source contains a long base64-like string combined with decode/exec patterns", "base64-blob")
	}
	if hexBlobRegex.MatchString(content) && strings.Contains(lower, "from_hex") {
		add("encoded_payload",
			"Rust source contains a long hex-encoded blob combined with from_hex decoding", "hex-blob")
	}

	// 8. Unsafe memory / FFI abuse (informational, lower severity)
	if strings.Contains(content, "unsafe {") && (strings.Contains(content, "transmute") || strings.Contains(content, "from_raw")) {
		add("unsafe_memory_operation",
			"Rust source uses unsafe memory transmutation or raw pointer operations", "unsafe+transmute")
	}

	return findings, suspicious
}

func dedupeReasons(in []types.Reason) []types.Reason {
	seen := map[string]bool{}
	var out []types.Reason
	for _, r := range in {
		key := r.ID + ":" + r.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
