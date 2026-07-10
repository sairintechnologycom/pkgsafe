package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

type JSONResult struct {
	Ecosystem        string                        `json:"ecosystem"`
	Package          string                        `json:"package"`
	Version          string                        `json:"version"`
	Mode             string                        `json:"mode"`
	Decision         types.Decision                `json:"decision"`
	RiskScore        int                           `json:"risk_score"`
	Thresholds       types.Thresholds              `json:"thresholds"`
	Reasons          []types.Reason                `json:"reasons"`
	Vulnerabilities  []types.Vulnerability         `json:"vulnerabilities,omitempty"`
	Recommended      string                        `json:"recommended_action"`
	Enforcement      string                        `json:"enforcement,omitempty"`
	PackageIdentity  types.PackageIdentity         `json:"package_identity,omitempty"`
	LifecycleScripts []string                      `json:"lifecycle_scripts,omitempty"`
	Suspicious       []string                      `json:"suspicious_patterns,omitempty"`
	BehaviorAnalysis types.BehaviorAnalysisSummary `json:"behavior_analysis"`
	ArtifactAnalysis types.ArtifactSummary         `json:"artifact_analysis,omitempty"`
	PolicyInfo       *types.PolicyEvidence         `json:"policy,omitempty"`
	RegistryInfo     *types.RegistryEvidence       `json:"registry,omitempty"`
	TrustInfo        *types.TrustEvidence          `json:"trust,omitempty"`
	ExceptionInfo    *types.ExceptionEvidence      `json:"exception,omitempty"`
}

func isSandboxReason(id string) bool {
	switch id {
	case "credential_canary_read",
		"credential_canary_exfiltration_attempt",
		"cloud_metadata_access",
		"npm_token_access",
		"ssh_key_access",
		"env_secret_access",
		"network_call_from_lifecycle",
		"shell_download_execute",
		"encoded_payload_execution",
		"unexpected_binary_write",
		"child_process_spawn",
		"home_directory_enumeration",
		"environment_variable_enumeration",
		"lifecycle_script_nonzero_exit":
		return true
	default:
		return false
	}
}

func Write(w io.Writer, result types.ScanResult, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(JSONResult{
			Ecosystem:        result.Package.Ecosystem,
			Package:          result.Package.Name,
			Version:          emptyLatest(result.Package.Version),
			Mode:             result.Mode,
			Decision:         result.Decision,
			RiskScore:        result.Score,
			Thresholds:       result.Thresholds,
			Reasons:          result.Reasons,
			Vulnerabilities:  result.Vulnerabilities,
			Recommended:      RecommendedAction(result),
			Enforcement:      result.Enforcement,
			PackageIdentity:  result.Package,
			LifecycleScripts: result.Lifecycle,
			Suspicious:       result.Suspicious,
			BehaviorAnalysis: types.BehaviorAnalysisFromSandbox(result.Sandbox),
			ArtifactAnalysis: result.Artifact,
			PolicyInfo:       result.PolicyInfo,
			RegistryInfo:     result.RegistryInfo,
			TrustInfo:        result.TrustInfo,
			ExceptionInfo:    result.ExceptionInfo,
		})
	}

	if result.Package.Ecosystem == "npm-lock" {
		return writeLockfileReport(w, result)
	}

	if result.Sandbox.Enabled && result.Package.Ecosystem != "pypi" {
		fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(string(result.Decision)))
		if result.Mode != "" {
			fmt.Fprintf(w, "Mode: %s\n", strings.ToUpper(result.Mode))
		}
		if result.RegistryInfo != nil && result.RegistryInfo.Name != "" {
			fmt.Fprintf(w, "Registry: %s %s registry\n", result.RegistryInfo.Name, result.RegistryInfo.Type)
		}
		if result.PolicyInfo != nil && result.PolicyInfo.Name != "" {
			fmt.Fprintf(w, "Policy Pack: %s@%s\n", result.PolicyInfo.Name, result.PolicyInfo.Version)
		}
		if result.ExceptionInfo != nil && result.ExceptionInfo.Matched {
			fmt.Fprintf(w, "Exception: %s, valid until %s\n", result.ExceptionInfo.RuleID, result.ExceptionInfo.ValidUntil)
		}
		fmt.Fprintf(w, "Package: %s/%s@%s\n", result.Package.Ecosystem, result.Package.Name, emptyLatest(result.Package.Version))
		fmt.Fprintf(w, "Risk Score: %d/100\n\n", result.Score)

		fmt.Fprintln(w, "Static Analysis:")
		staticCount := 0
		for _, r := range result.Reasons {
			if !isSandboxReason(r.ID) && r.ID != "trusted_package_reduction" {
				fmt.Fprintf(w, "- %s\n", r.Description)
				staticCount++
			}
		}
		if staticCount == 0 {
			fmt.Fprintln(w, "- No risks detected during static analysis")
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "Behavior Analysis (%s", result.Sandbox.BehaviorMode)
		if !result.Sandbox.Isolated {
			fmt.Fprint(w, "; not isolated")
		}
		fmt.Fprintln(w, "):")
		if result.Sandbox.Warning != "" {
			fmt.Fprintf(w, "- Warning: %s\n", result.Sandbox.Warning)
		}
		if result.Sandbox.NotPerformed {
			fmt.Fprintln(w, "- Not performed")
			fmt.Fprintf(w, "- Reason: %s\n", result.Sandbox.NotPerfReason)
		} else {
			for _, run := range result.Sandbox.ScriptsExecuted {
				fmt.Fprintf(w, "- Script: %s\n", run.Name)
				if run.Error != "" {
					fmt.Fprintf(w, "- Error: %s (script was NOT analyzed)\n", run.Error)
					continue
				}
				fmt.Fprintf(w, "- Duration: %d ms\n", run.DurationMs)
				fmt.Fprintf(w, "- Exit Code: %d\n", run.ExitCode)
				if run.Isolated {
					fmt.Fprintf(w, "- Network Mode (enforced): %s\n", result.Sandbox.NetworkMode)
				} else {
					fmt.Fprintf(w, "- Network Mode (declared, not enforced): %s\n", result.Sandbox.NetworkMode)
				}
			}
			if len(result.Sandbox.ScriptsExecuted) == 0 {
				fmt.Fprintln(w, "- No lifecycle scripts defined to run")
			}
		}
		fmt.Fprintln(w)

		fmt.Fprintln(w, "Behavior Findings:")
		sandboxCount := 0
		for _, r := range result.Reasons {
			if isSandboxReason(r.ID) {
				fmt.Fprintf(w, "- [%s %+d] %s: %s\n", r.Severity, r.ScoreImpact, r.ID, r.Description)
				sandboxCount++
			}
		}
		if sandboxCount == 0 {
			fmt.Fprintln(w, "- No behavioral findings detected")
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "Recommended Action:\n%s\n", RecommendedAction(result))
		return nil
	}

	fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(string(result.Decision)))
	if result.Mode != "" {
		fmt.Fprintf(w, "Mode: %s\n", strings.ToUpper(result.Mode))
	}
	if result.RegistryInfo != nil && result.RegistryInfo.Name != "" {
		fmt.Fprintf(w, "Registry: %s %s registry\n", result.RegistryInfo.Name, result.RegistryInfo.Type)
	}
	if result.PolicyInfo != nil && result.PolicyInfo.Name != "" {
		fmt.Fprintf(w, "Policy Pack: %s@%s\n", result.PolicyInfo.Name, result.PolicyInfo.Version)
	}
	if result.ExceptionInfo != nil && result.ExceptionInfo.Matched {
		fmt.Fprintf(w, "Exception: %s, valid until %s\n", result.ExceptionInfo.RuleID, result.ExceptionInfo.ValidUntil)
	}
	if result.Enforcement != "" {
		fmt.Fprintf(w, "Enforcement: %s\n", result.Enforcement)
	}
	fmt.Fprintf(w, "Package: %s/%s@%s\n", result.Package.Ecosystem, result.Package.Name, emptyLatest(result.Package.Version))
	fmt.Fprintf(w, "Risk Score: %d/100\n", result.Score)
	if result.Package.Ecosystem == "pypi" && result.Sandbox.Enabled {
		fmt.Fprintln(w, "\nPyPI behavior analysis is not implemented yet. Static analysis completed only.")
	}
	if len(result.Lifecycle) > 0 {
		fmt.Fprintf(w, "Lifecycle Scripts: %s\n", strings.Join(result.Lifecycle, ", "))
	}
	if len(result.Reasons) > 0 {
		fmt.Fprintln(w, "\nReasons:")
		for _, r := range result.Reasons {
			if r.ID == "score_clamped" {
				fmt.Fprintln(w, "- Score clamped to 100")
				continue
			}
			fmt.Fprintf(w, "- [%s %+d] %s: %s", r.Severity, r.ScoreImpact, r.ID, r.Description)
			if r.Evidence != "" {
				fmt.Fprintf(w, " (%s)", r.Evidence)
			}
			fmt.Fprintln(w)
		}
	}
	if result.Package.Ecosystem == "pypi" {
		fmt.Fprintln(w, "\nArtifact Analysis:")
		fmt.Fprintf(w, "- Wheel available: %v\n", result.Artifact.WheelAvailable)
		fmt.Fprintf(w, "- Source distribution available: %v\n", result.Artifact.SourceDistributionAvailable)
		fmt.Fprintf(w, "- Yanked: %v\n", result.Artifact.Yanked)
		if result.Artifact.BuildBackend != "" {
			fmt.Fprintf(w, "- Build backend: %s\n", result.Artifact.BuildBackend)
		}
		fmt.Fprintf(w, "- setup.py present: %v\n", result.Artifact.SetupPyPresent)
		if result.Artifact.SandboxNote != "" {
			fmt.Fprintf(w, "- Behavior analysis: %s\n", result.Artifact.SandboxNote)
		}
	}
	if len(result.Vulnerabilities) > 0 {
		fmt.Fprintln(w, "\nVulnerabilities:")
		for _, v := range result.Vulnerabilities {
			header := v.ID
			var alts []string
			for _, a := range v.Aliases {
				if a != v.ID {
					alts = append(alts, a)
				}
			}
			if len(alts) > 0 {
				header = header + " / " + strings.Join(alts, " / ")
			}
			fmt.Fprintf(w, "- %s\n", header)
			fmt.Fprintf(w, "  Severity: %s\n", v.Severity)
			fmt.Fprintf(w, "  Summary: %s\n", v.Summary)
			fixedStr := "None"
			if len(v.FixedVersions) > 0 {
				fixedStr = strings.Join(v.FixedVersions, ", ")
			}
			fmt.Fprintf(w, "  Fixed Version: %s\n", fixedStr)
		}
	}
	if len(result.SafeAlternates) > 0 {
		fmt.Fprintf(w, "\nPossible safe alternatives: %s\n", strings.Join(result.SafeAlternates, ", "))
	}
	fmt.Fprintf(w, "\nRecommended Action:\n%s\n", RecommendedAction(result))
	return nil
}

func emptyLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

// GetColorTheme returns ANSI escape sequences for bold/green/red/yellow/reset
// when the writer is a terminal with color support; all strings are empty when
// colors are disabled (NO_COLOR, dumb terminal, or non-tty writer).
func GetColorTheme(w io.Writer) (bold, green, red, yellow, reset string, enabled bool) {
	if f, ok := w.(*os.File); ok {
		if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
			enabled = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
		}
	}
	if enabled {
		bold = "\033[1m"
		green = "\033[32m"
		red = "\033[31m"
		yellow = "\033[33m"
		reset = "\033[0m"
	}
	return
}

func RecommendedAction(result types.ScanResult) string {
	if result.Decision == types.DecisionBlock {
		return "Do not install this package."
	}
	if result.Sandbox.Enabled && result.Sandbox.NotPerformed && result.Package.Ecosystem != "pypi" {
		return "Review package before installing. Requested behavior analysis was not performed."
	}
	if result.Recommended != "" {
		return result.Recommended
	}

	var fixedVersions []string
	for _, v := range result.Vulnerabilities {
		if len(v.FixedVersions) > 0 {
			fixedVersions = append(fixedVersions, v.FixedVersions...)
		}
	}
	if len(fixedVersions) > 0 {
		fixedVersions = unique(fixedVersions)
		return fmt.Sprintf("Upgrade to %s@%s or later.", result.Package.Name, strings.Join(fixedVersions, ", "))
	}

	switch result.Decision {
	case types.DecisionBlock:
		return "Do not install this package."
	case types.DecisionWarn:
		return "Review package before installing."
	default:
		return "Package appears safe to install based on current checks."
	}
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

func writeLockfileReport(w io.Writer, result types.ScanResult) error {
	var bold, green, red, yellow, reset string
	color := false
	if f, ok := w.(*os.File); ok {
		if os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
			color = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
		}
	}
	if color {
		bold = "\033[1m"
		green = "\033[32m"
		red = "\033[31m"
		yellow = "\033[33m"
		reset = "\033[0m"
	}

	fmt.Fprintf(w, "%s%sPkgSafe Lockfile Scan Report%s\n", bold, green, reset)
	fmt.Fprintf(w, "%s============================%s\n\n", bold, reset)

	// Decision & Score
	decisionStr := strings.ToUpper(string(result.Decision))
	decisionColor := green
	if result.Decision == types.DecisionBlock {
		decisionColor = red
	} else if result.Decision == types.DecisionWarn {
		decisionColor = yellow
	}
	fmt.Fprintf(w, "Decision:   %s%s%s%s\n", bold, decisionColor, decisionStr, reset)
	
	// Risk score colorized
	scoreColor := green
	scoreLabel := "Low Risk"
	if result.Score >= 70 {
		scoreColor = red
		scoreLabel = "High Risk"
	} else if result.Score >= 30 {
		scoreColor = yellow
		scoreLabel = "Medium Risk"
	}
	fmt.Fprintf(w, "Risk Score: %s%s%d/100 (%s)%s [Scale: 0-29 Low, 30-69 Med, 70-100 High]\n\n", bold, scoreColor, result.Score, scoreLabel, reset)

	// Summary stats
	var total, allowed, blocked, warned int
	for _, s := range result.Suspicious {
		if strings.HasPrefix(s, "lockfile_summary:") {
			fmt.Sscanf(s, "lockfile_summary:total:%d,allowed:%d,blocked:%d,warned:%d", &total, &allowed, &blocked, &warned)
		}
	}

	if total > 0 {
		fmt.Fprintf(w, "%sDependency Graph Summary:%s\n", bold, reset)
		fmt.Fprintf(w, "  Total Dependencies: %d\n", total)
		fmt.Fprintf(w, "  Allowed:            %s%d%s\n", green, allowed, reset)
		if blocked > 0 {
			fmt.Fprintf(w, "  Blocked:            %s%d%s\n", red, blocked, reset)
		} else {
			fmt.Fprintf(w, "  Blocked:            %d\n", blocked)
		}
		if warned > 0 {
			fmt.Fprintf(w, "  Warnings / Risks:   %s%d%s\n", yellow, warned, reset)
		} else {
			fmt.Fprintf(w, "  Warnings / Risks:   %d\n", warned)
		}
		fmt.Fprintln(w)
	}

	// Finding Table
	findings := []types.Reason{}
	for _, r := range result.Reasons {
		if r.ID != "lockfile_summary" && r.ID != "score_clamped" && r.ID != "large_dependency_graph" && r.ID != "empty_lockfile" {
			findings = append(findings, r)
		}
	}

	if len(findings) > 0 {
		fmt.Fprintf(w, "%sTop Dependency Findings:%s\n", bold, reset)
		// Table header
		fmt.Fprintf(w, "  %-8s %-32s %-10s %-24s\n", "STATUS", "DEPENDENCY", "DECISION", "REASON")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 80))

		for _, r := range findings {
			status := "✓ PASS"
			statusColor := green
			decision := "ALLOW"
			decisionColor := green

			if r.ID == "blocked_package" || r.ID == "known_malware_indicator" || strings.HasPrefix(r.ID, "known_vulnerability_high") || strings.HasPrefix(r.ID, "known_vulnerability_critical") {
				status = "✗ FAIL"
				statusColor = red
				decision = "BLOCK"
				decisionColor = red
			} else {
				status = "⚠ WARN"
				statusColor = yellow
				decision = "WARN"
				decisionColor = yellow
			}

			dep := r.Evidence
			if dep == "" {
				dep = r.Description
			}

			fmt.Fprintf(w, "  %s%-8s%s %-32s %s%-10s%s %-24s\n", 
				statusColor, status, reset, 
				truncate(dep, 32), 
				decisionColor, decision, reset, 
				truncate(r.ID, 24),
			)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%sRecommended Action:%s\n%s\n", bold, reset, RecommendedAction(result))
	return nil
}

func truncate(s string, limit int) string {
	if len(s) > limit {
		return s[:limit-3] + "..."
	}
	return s
}
