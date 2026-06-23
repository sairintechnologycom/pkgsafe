package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/types"
)

type JSONResult struct {
	Ecosystem        string                `json:"ecosystem"`
	Package          string                `json:"package"`
	Version          string                `json:"version"`
	Mode             string                `json:"mode"`
	Decision         types.Decision        `json:"decision"`
	RiskScore        int                   `json:"risk_score"`
	Thresholds       types.Thresholds      `json:"thresholds"`
	Reasons          []types.Reason        `json:"reasons"`
	Vulnerabilities  []types.Vulnerability `json:"vulnerabilities,omitempty"`
	Recommended      string                `json:"recommended_action"`
	Enforcement      string                `json:"enforcement,omitempty"`
	PackageIdentity  types.PackageIdentity `json:"package_identity,omitempty"`
	LifecycleScripts []string              `json:"lifecycle_scripts,omitempty"`
	Suspicious       []string              `json:"suspicious_patterns,omitempty"`
	Sandbox          types.SandboxSummary  `json:"sandbox,omitempty"`
	ArtifactAnalysis types.ArtifactSummary `json:"artifact_analysis,omitempty"`
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
			Sandbox:          result.Sandbox,
			ArtifactAnalysis: result.Artifact,
		})
	}

	if result.Sandbox.Enabled && result.Package.Ecosystem != "pypi" {
		fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(string(result.Decision)))
		if result.Mode != "" {
			fmt.Fprintf(w, "Mode: %s\n", strings.ToUpper(result.Mode))
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

		fmt.Fprintln(w, "Sandbox Analysis:")
		if result.Sandbox.NotPerformed {
			fmt.Fprintln(w, "- Not performed")
			fmt.Fprintf(w, "- Reason: %s\n", result.Sandbox.NotPerfReason)
		} else {
			for _, run := range result.Sandbox.ScriptsExecuted {
				fmt.Fprintf(w, "- Script: %s\n", run.Name)
				fmt.Fprintf(w, "- Duration: %d ms\n", run.DurationMs)
				fmt.Fprintf(w, "- Exit Code: %d\n", run.ExitCode)
				fmt.Fprintf(w, "- Network Mode: %s\n", result.Sandbox.NetworkMode)
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
			fmt.Fprintln(w, "- No findings detected in sandbox")
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "Recommended Action:\n%s\n", RecommendedAction(result))
		return nil
	}

	fmt.Fprintf(w, "Decision: %s\n", strings.ToUpper(string(result.Decision)))
	if result.Mode != "" {
		fmt.Fprintf(w, "Mode: %s\n", strings.ToUpper(result.Mode))
	}
	if result.Enforcement != "" {
		fmt.Fprintf(w, "Enforcement: %s\n", result.Enforcement)
	}
	fmt.Fprintf(w, "Package: %s/%s@%s\n", result.Package.Ecosystem, result.Package.Name, emptyLatest(result.Package.Version))
	fmt.Fprintf(w, "Risk Score: %d/100\n", result.Score)
	if result.Package.Ecosystem == "pypi" && result.Sandbox.Enabled {
		fmt.Fprintln(w, "\nPyPI sandbox execution is not implemented yet. Static analysis completed only.")
	}
	if len(result.Lifecycle) > 0 {
		fmt.Fprintf(w, "Lifecycle Scripts: %s\n", strings.Join(result.Lifecycle, ", "))
	}
	if len(result.Reasons) > 0 {
		fmt.Fprintln(w, "\nReasons:")
		for _, r := range result.Reasons {
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
			fmt.Fprintf(w, "- Sandbox: %s\n", result.Artifact.SandboxNote)
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

func RecommendedAction(result types.ScanResult) string {
	if result.Sandbox.Enabled && result.Sandbox.NotPerformed && result.Package.Ecosystem != "pypi" {
		return "Review package before installing. Run sandbox analysis on a supported Linux or Docker-enabled environment."
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
