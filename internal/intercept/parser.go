package intercept

import (
	"fmt"
	"strings"
)

type SafetyFlags struct {
	Mode            string
	PolicyPath      string
	Sandbox         bool
	Offline         bool
	DryRun          bool
	Yes             bool
	JSON            bool
	ForceRiskAccept bool
	Reason          string
	PolicyPack      string
	RequestedBy     string
	Environment     string
	RegistryConfig  string
	EnterpriseMode  bool
}

func ExtractSafetyFlags(args []string) ([]string, SafetyFlags) {
	var cleanArgs []string
	sf := SafetyFlags{
		EnterpriseMode: true,
	}
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
		} else if arg == "--policy-pack" && i+1 < len(args) {
			sf.PolicyPack = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--policy-pack=") {
			sf.PolicyPack = strings.TrimPrefix(arg, "--policy-pack=")
			i++
		} else if arg == "--requested-by" && i+1 < len(args) {
			sf.RequestedBy = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--requested-by=") {
			sf.RequestedBy = strings.TrimPrefix(arg, "--requested-by=")
			i++
		} else if arg == "--environment" && i+1 < len(args) {
			sf.Environment = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--environment=") {
			sf.Environment = strings.TrimPrefix(arg, "--environment=")
			i++
		} else if arg == "--reason" && i+1 < len(args) {
			sf.Reason = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--reason=") {
			sf.Reason = strings.TrimPrefix(arg, "--reason=")
			i++
		} else if arg == "--registry-config" && i+1 < len(args) {
			sf.RegistryConfig = args[i+1]
			i += 2
		} else if strings.HasPrefix(arg, "--registry-config=") {
			sf.RegistryConfig = strings.TrimPrefix(arg, "--registry-config=")
			i++
		} else if arg == "--enterprise-mode" {
			sf.EnterpriseMode = true
			i++
		} else if arg == "--no-enterprise-mode" || arg == "--enterprise-mode=false" {
			sf.EnterpriseMode = false
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
