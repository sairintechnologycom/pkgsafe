package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/risk"
	"github.com/niyam-ai/pkgsafe/internal/types"
	"github.com/niyam-ai/pkgsafe/internal/typosquat"
)

var (
	base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{30,}=*`)
	hexRegex    = regexp.MustCompile(`[0-9a-fA-F]{40,}`)
)

type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	License         any               `json:"license"`
	Repository      any               `json:"repository"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func AnalyzePackageDir(dir string, pol policy.Policy) (types.ScanResult, error) {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("read package.json: %w", err)
	}
	return AnalyzePackageJSON(b, pol)
}

func AnalyzePackageJSON(b []byte, pol policy.Policy) (types.ScanResult, error) {
	var pj PackageJSON
	if err := json.Unmarshal(b, &pj); err != nil {
		return types.ScanResult{}, fmt.Errorf("parse package.json: %w", err)
	}
	if pj.Name == "" {
		pj.Name = "unknown"
	}

	pkg := types.PackageIdentity{Ecosystem: "npm", Name: pj.Name, Version: pj.Version}
	var findings []types.Reason
	var lifecycle []string
	var suspicious []string

	for _, name := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if script, ok := pj.Scripts[name]; ok {
			lifecycle = append(lifecycle, name)
			findings = risk.AddReason(findings, "lifecycle_script_present", fmt.Sprintf("Package defines a %s script", name), name+"="+script)
			lower := strings.ToLower(script)
			normalized := normalizeScript(script)

			if base64Regex.MatchString(script) {
				suspicious = append(suspicious, "base64-payload")
				findings = risk.AddReason(findings, "obfuscated_script", "Lifecycle script contains a long base64-like encoded string", "base64-payload")
			}
			if hexRegex.MatchString(script) {
				suspicious = append(suspicious, "hex-payload")
				findings = risk.AddReason(findings, "obfuscated_script", "Lifecycle script contains a long hex-encoded string", "hex-payload")
			}

			for _, pat := range credentialPatterns(pol) {
				if protectedPatternMatch(lower, normalized, pat) {
					suspicious = append(suspicious, pat)
					findings = risk.AddReason(findings, "credential_path_reference", "Lifecycle script references a protected credential path", pat)
				}
			}
			for _, pat := range networkPatterns() {
				if matchAny(lower, normalized, pat) {
					suspicious = append(suspicious, pat)
					findings = risk.AddReason(findings, "network_command_in_lifecycle", fmt.Sprintf("Lifecycle script uses %s", strings.TrimSpace(pat)), pat)
					break
				}
			}
			for _, pat := range secretPatterns() {
				if matchAny(lower, normalized, pat) {
					suspicious = append(suspicious, pat)
					findings = risk.AddReason(findings, "secret_keyword_reference", "Lifecycle script references secret-related keywords", pat)
				}
			}
			for _, pat := range obfuscationPatterns() {
				if matchAny(lower, normalized, pat) {
					suspicious = append(suspicious, pat)
					findings = risk.AddReason(findings, "obfuscated_script", "Lifecycle script contains obfuscation indicators", pat)
				}
			}
		}
	}

	alts := typosquat.Check(pj.Name)
	if len(alts) > 0 {
		findings = risk.AddReason(findings, "typosquat_candidate", "Package name resembles a popular package", strings.Join(alts, ", "))
	}

	if pj.Repository == nil || fmt.Sprint(pj.Repository) == "" {
		findings = risk.AddReason(findings, "missing_repository", "Package metadata does not include a source repository", "")
	}
	if pj.License == nil || fmt.Sprint(pj.License) == "" {
		findings = risk.AddReason(findings, "missing_license", "Package metadata does not include a license", "")
	}

	return risk.Evaluate(pkg, dedupeReasons(findings), unique(lifecycle), unique(suspicious), alts, pol), nil
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func matchAny(rawLower, normalized, pattern string) bool {
	pat := strings.ToLower(pattern)
	return strings.Contains(rawLower, pat) || strings.Contains(normalized, pat)
}

func protectedPatternMatch(rawLower, normalized, pattern string) bool {
	pat := strings.ToLower(pattern)
	if pat == ".env" {
		matchRaw := strings.Contains(rawLower, ".env") && !strings.Contains(rawLower, "process.env")
		matchNorm := strings.Contains(normalized, ".env") && !strings.Contains(normalized, "process.env")
		return matchRaw || matchNorm
	}
	return strings.Contains(rawLower, pat) || strings.Contains(normalized, pat)
}

func normalizeScript(script string) string {
	s := strings.ToLower(script)
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "\\", "")
	s = strings.ReplaceAll(s, "$()", "")
	s = strings.ReplaceAll(s, "${}", "")
	s = strings.ReplaceAll(s, "+", "")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func dedupeReasons(in []types.Reason) []types.Reason {
	seen := map[string]bool{}
	out := []types.Reason{}
	for _, r := range in {
		key := r.ID + ":" + r.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

func credentialPatterns(pol policy.Policy) []string {
	patterns := append([]string{}, pol.ProtectedPaths...)
	patterns = append(patterns, pol.BlockPatterns...)
	return patterns
}

func networkPatterns() []string {
	return []string{"curl", "wget", "invoke-webrequest", "http://", "https://"}
}

func secretPatterns() []string {
	return []string{"aws_access_key_id", "aws_secret_access_key", "github_token", "vault_token", "token", "secret"}
}

func obfuscationPatterns() []string {
	return []string{
		"base64", "eval", "child_process", "powershell", "pwsh", "bash -c", "sh -c", "netcat", " nc ",
		"python", "perl", "ruby", "php", "osascript", "atob", "btoa", "string.fromcharcode", "buffer.from",
	}
}
