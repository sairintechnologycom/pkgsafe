package intercept

import (
	"fmt"
	"os"
	"strings"

	"github.com/sairintechnologycom/pkgsafe/internal/output"
	"github.com/sairintechnologycom/pkgsafe/internal/policy"
	"github.com/sairintechnologycom/pkgsafe/internal/types"
)

func isCredentialAccessRule(id string) bool {
	switch id {
	case "credential_path_reference", "credential_canary_read", "credential_canary_exfiltration_attempt",
		"ssh_key_access", "npm_token_access", "env_secret_access", "pypi_setup_py_credential_access":
		return true
	}
	return false
}

func CanProceed(results []types.ScanResult, overallDecision types.Decision, sf SafetyFlags, pol policy.Policy) (bool, string, int) {
	// If force risk accept is enabled, check overrides
	if overallDecision == types.DecisionBlock {
		if sf.ForceRiskAccept {
			if !pol.InstallInterception.AllowForceRiskAccept {
				return false, "Force risk accept is disabled by policy.", ExitBlocked
			}
			if pol.InstallInterception.ForceRiskAcceptRequiresReason && strings.TrimSpace(sf.Reason) == "" {
				return false, "Force risk accept requires a reason. Specify --reason \"your reason\".", ExitBlocked
			}

			// Block malware bypass and credential access bypass if disabled
			for _, res := range results {
				if res.Decision == types.DecisionBlock {
					for _, reason := range res.Reasons {
						if pol.InstallInterception.BlockKnownMalwareAlways && reason.ID == "known_malware_indicator" {
							return false, "Cannot force install: package contains known malware and bypass is disabled by policy.", ExitBlocked
						}
						if pol.InstallInterception.BlockCredentialAccessAlways && isCredentialAccessRule(reason.ID) {
							return false, "Cannot force install: package accesses credentials and bypass is disabled by policy.", ExitBlocked
						}
					}
				}
			}
			return true, "", ExitSuccess
		}
		return false, "Install was blocked by policy.", ExitBlocked
	}

	if overallDecision == types.DecisionWarn {
		if sf.ForceRiskAccept {
			return true, "", ExitSuccess
		}

		isAI := os.Getenv("PKGSAFE_REQUESTED_BY") == "ai_agent"
		if isAI {
			// Spec: Warn should not proceed automatically.
			// Return false unless explicit override (force-risk-accept) is passed.
			return false, "AI agent context detected. WARN decisions require --force-risk-accept and --reason to proceed.", ExitBlocked
		}

		if sf.Yes {
			if pol.InstallInterception.AllowYesOnWarn {
				return true, "", ExitSuccess
			}
			return false, "WARN decision requires interactive confirmation by policy (--yes disabled).", ExitDeclined
		}

		if sf.NonInteractive || !IsInteractive() {
			return false, "Non-interactive mode detected. WARN decisions require --yes to proceed.", ExitDeclined
		}

		// Interactive prompt
		if pol.InstallInterception.ConfirmOnWarn {
			ok, err := PromptConfirm("Proceed with install? [y/N] ")
			if err != nil {
				return false, fmt.Sprintf("Error reading confirmation: %v", err), ExitDeclined
			}
			if !ok {
				return false, "Installation declined by user.", ExitDeclined
			}
		}
	}

	return true, "", ExitSuccess
}

func PrintHumanOutput(cmd *InstallCommand, results []types.ScanResult, overallDecision types.Decision) {
	bold, green, red, yellow, reset, color := output.GetColorTheme(os.Stdout)

	fmt.Println("PkgSafe Install Guard")
	fmt.Println()
	fmt.Printf("Command: %s\n", strings.Join(RedactCommand(cmd.RawCommand), " "))

	decisionStr := strings.ToUpper(string(overallDecision))
	if color {
		switch overallDecision {
		case types.DecisionBlock:
			decisionStr = red + bold + decisionStr + reset
		case types.DecisionWarn:
			decisionStr = yellow + bold + decisionStr + reset
		default:
			decisionStr = green + bold + decisionStr + reset
		}
	}
	fmt.Printf("Decision: %s\n", decisionStr)
	fmt.Printf("Packages checked: %d\n", len(results))
	fmt.Println()

	for _, res := range results {
		fmt.Printf("- %s@%s\n", res.Package.Name, res.Package.Version)
		fmt.Printf("  Score: %d/100\n", res.Score)

		resDecisionStr := strings.ToUpper(string(res.Decision))
		if color {
			switch res.Decision {
			case types.DecisionBlock:
				resDecisionStr = red + bold + resDecisionStr + reset
			case types.DecisionWarn:
				resDecisionStr = yellow + bold + resDecisionStr + reset
			default:
				resDecisionStr = green + bold + resDecisionStr + reset
			}
		}
		fmt.Printf("  Decision: %s\n", resDecisionStr)
		if len(res.Reasons) > 0 {
			fmt.Println("  Reasons:")
			for _, reason := range res.Reasons {
				// Don't print neutral/negative adjustment reasons or keep it to actual risk findings
				if reason.ScoreImpact > 0 || reason.ID == "trusted_package_reduction" {
					fmt.Printf("  - %s\n", reason.Description)
				}
			}
		}
		fmt.Println()
	}
}
