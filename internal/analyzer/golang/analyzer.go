package golang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/risk"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

// maxFiles and maxBytes are artifact budget limits for Go module zips.
// Modules that exceed these limits fail closed rather than silently passing.
// These are package-level vars so tests can override them.
var (
	maxFiles = 20_000
	maxBytes = int64(512 * 1024 * 1024) // 512 MiB
)

var (
	// base64Regex matches long embedded base64 strings in Go source.
	base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	// hexBlobRegex matches long hex-encoded blobs.
	hexBlobRegex = regexp.MustCompile(`[0-9a-fA-F]{48,}`)
)

// credentialPaths are protected paths that should never be read by a module.
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
	"169.254.169.254",
	"metadata.google.internal",
	"metadata/instance",
	"latest/meta-data",
}

// secretKeywords are environment-variable names that signal credential access.
var secretKeywords = []string{
	"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
	"github_token", "gitlab_token",
	"vault_token", "vault_addr",
	"database_url", "db_password",
}

type Analysis struct {
	Result   types.ScanResult
	Findings []types.Reason
}

// AnalyzeDir walks an extracted Go module directory and inspects .go files for
// malicious patterns. Returns an Analysis with all findings.
func AnalyzeDir(dir string, name, version string, pol policy.Policy) (Analysis, error) {
	pkg := types.PackageIdentity{Ecosystem: "go", Name: name, Version: version}
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
				fmt.Sprintf("Module exceeds file budget (%d files); artifact not fully scanned", maxFiles), "file_count")
			return filepath.SkipAll
		}

		info, err := d.Info()
		if err == nil {
			totalBytes += info.Size()
		}
		if totalBytes > maxBytes {
			findings = risk.AddReason(findings, "artifact_oversized",
				fmt.Sprintf("Module exceeds size budget (%d MiB); artifact not fully scanned", maxBytes/(1024*1024)), "size")
			return filepath.SkipAll
		}

		rel, _ := filepath.Rel(dir, path)
		lowerBase := strings.ToLower(filepath.Base(path))

		if strings.HasSuffix(lowerBase, ".go") {
			f, sf := analyzeGoFile(path, rel)
			findings = append(findings, f...)
			suspicious = append(suspicious, sf...)
		}

		return nil
	})

	res := risk.Evaluate(pkg, dedupeReasons(findings), nil, unique(suspicious), nil, pol)
	return Analysis{Result: res, Findings: findings}, err
}

// analyzeGoFile inspects a single .go source file for dangerous patterns.
// It combines fast string matching with a best-effort AST parse for init()
// function body analysis.
func analyzeGoFile(path, rel string) ([]types.Reason, []string) {
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

	// ── 2. Shell / exec patterns ──────────────────────────────────────────────
	for _, pat := range []string{
		"exec.Command", "exec.CommandContext",
		"syscall.Exec", "syscall.ForkExec",
		"os/exec",
	} {
		if strings.Contains(content, pat) {
			add("shell_execution",
				fmt.Sprintf("Go source spawns subprocesses via %s", pat), pat)
			break
		}
	}

	// ── 3. Network calls ──────────────────────────────────────────────────────
	for _, pat := range []string{
		"http.Get", "http.Post", "http.Do", "http.NewRequest",
		"net.Dial", "net.DialTCP", "net.DialUDP",
		"net.Listen", "net.ResolveTCPAddr",
	} {
		if strings.Contains(content, pat) {
			add("network_command_in_lifecycle",
				fmt.Sprintf("Go source performs network operations (%s)", pat+"()"), pat)
			break
		}
	}

	// ── 4. Credential path references ─────────────────────────────────────────
	for _, p := range credentialPaths {
		if strings.Contains(lower, p) {
			add("credential_path_reference",
				fmt.Sprintf("Go source references protected credential path: %s", p), p)
		}
	}

	// ── 5. Cloud metadata endpoint access ─────────────────────────────────────
	for _, ep := range cloudMetadataEndpoints {
		if strings.Contains(lower, ep) {
			add("cloud_metadata_access",
				fmt.Sprintf("Go source references cloud instance metadata endpoint: %s", ep), ep)
		}
	}

	// ── 6. Environment variable + network exfiltration ────────────────────────
	envAccess := strings.Contains(content, "os.Getenv") ||
		strings.Contains(content, "os.LookupEnv") ||
		strings.Contains(content, "os.Environ()")
	netAccess := strings.Contains(content, "http.Get") ||
		strings.Contains(content, "http.Post") ||
		strings.Contains(content, "net.Dial") ||
		strings.Contains(content, "net/http") ||
		strings.Contains(content, "net.Listen")
	if envAccess && netAccess {
		add("env_secret_exfil",
			"Go source reads environment variables and performs network operations (possible secret exfiltration)", "os.Getenv+net")
	}

	// ── 7. Secret keyword references ──────────────────────────────────────────
	for _, k := range secretKeywords {
		if strings.Contains(lower, k) {
			add("secret_keyword_reference",
				fmt.Sprintf("Go source references secret-related keyword: %s", k), k)
			break
		}
	}

	// ── 8. Encoded payloads ───────────────────────────────────────────────────
	if base64Regex.MatchString(content) &&
		(strings.Contains(lower, "base64") || strings.Contains(lower, "encoding/base64")) &&
		(strings.Contains(lower, "decodestring") || strings.Contains(lower, "decode(") || strings.Contains(lower, ".decode")) {
		add("encoded_payload",
			"Go source contains a long base64-like string combined with base64 decode import", "base64-blob")
	}
	if hexBlobRegex.MatchString(content) &&
		(strings.Contains(lower, "hex.decodestring") || strings.Contains(lower, "encoding/hex")) {
		add("encoded_payload",
			"Go source contains a long hex-encoded blob combined with hex decode import", "hex-blob")
	}

	// ── 9. Unsafe pointer operations ──────────────────────────────────────────
	if strings.Contains(content, "unsafe.Pointer") || strings.Contains(content, "syscall.Syscall") {
		findings = risk.AddReason(findings, "unsafe_memory_operation",
			"Go source uses unsafe.Pointer or raw syscall invocation", rel+": unsafe")
		suspicious = append(suspicious, "unsafe/syscall")
	}

	// ── 10. init() side-effects with network access ───────────────────────────
	// Best-effort AST parse to detect init() bodies that make network calls.
	netInSource := strings.Contains(content, "http.Get") ||
		strings.Contains(content, "http.Post") ||
		strings.Contains(content, "net.Dial") ||
		strings.Contains(content, "net/http")
	if netInSource && strings.Contains(content, "func init()") {
		if initHasNetworkCall(content) {
			add("init_side_effect",
				"Go source defines an init() function that performs network calls (executes automatically on import)", "init+network")
		}
	}

	return findings, suspicious
}

// initHasNetworkCall does a lightweight AST parse to check whether any init()
// function body contains a network-related call expression. Falls back to
// string matching if parsing fails.
func initHasNetworkCall(src string) bool {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		// Fallback: conservative string check.
		return strings.Contains(src, "func init()") &&
			(strings.Contains(src, "http.Get") ||
				strings.Contains(src, "net.Dial") ||
				strings.Contains(src, "http.Post"))
	}

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "init" || fn.Body == nil {
			continue
		}
		// Walk the init() body for call expressions that look like network ops.
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callStr := exprToString(call.Fun)
			for _, pat := range []string{
				"http.Get", "http.Post", "http.Do", "http.NewRequest",
				"net.Dial", "net.DialTCP", "net.Listen",
			} {
				if strings.Contains(callStr, pat) {
					found = true
					return false
				}
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// exprToString converts a simple AST expression to a dot-separated string
// (e.g. http.Get, net.Dial). Returns empty string for complex expressions.
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	default:
		return ""
	}
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
