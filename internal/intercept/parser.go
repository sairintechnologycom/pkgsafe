package intercept

import (
	"fmt"
	"strings"
)

type SafetyFlags struct {
	Mode             string
	PolicyPath       string
	Sandbox          bool
	Offline          bool
	DryRun           bool
	Yes              bool
	JSON             bool
	ForceRiskAccept  bool
	Reason           string
}

func ExtractSafetyFlags(args []string) ([]string, SafetyFlags) {
	var cleanArgs []string
	var sf SafetyFlags
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "--sandbox" {
			sf.Sandbox = true
			i++
		} else if arg == "--offline" {
			sf.Offline = true
			i++
		} else if arg == "--dry-run" {
			sf.DryRun = true
			i++
		} else if arg == "--yes" || arg == "-y" {
			sf.Yes = true
			i++
		} else if arg == "--json" {
			sf.JSON = true
			i++
		} else if arg == "--force-risk-accept" {
			sf.ForceRiskAccept = true
			i++
		} else if arg == "--mode" && i+1 < len(args) {
			sf.Mode = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--mode=") {
			sf.Mode = strings.TrimPrefix(arg, "--mode=")
			i++
		} else if arg == "--policy" && i+1 < len(args) {
			sf.PolicyPath = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--policy=") {
			sf.PolicyPath = strings.TrimPrefix(arg, "--policy=")
			i++
		} else if arg == "--reason" && i+1 < len(args) {
			sf.Reason = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--reason=") {
			sf.Reason = strings.TrimPrefix(arg, "--reason=")
			i++
		} else {
			cleanArgs = append(cleanArgs, arg)
			i++
		}
	}
	return cleanArgs, sf
}

func ParseCommand(pm string, args []string) (*InstallCommand, error) {
	switch pm {
	case "npm":
		return ParseNPM(args)
	case "pip":
		return ParsePip(args)
	case "python":
		if len(args) >= 2 && args[0] == "-m" && args[1] == "pip" {
			cmd, err := ParsePip(args[2:])
			if err != nil {
				return nil, err
			}
			cmd.PackageManager = "python-pip"
			return cmd, nil
		}
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported python command: %s", strings.Join(args, " "))}
	default:
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported package manager: %s", pm)}
	}
}
