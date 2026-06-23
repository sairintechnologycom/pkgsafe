package intercept

import (
	"fmt"
	"strings"
)

func ParsePip(args []string) (*InstallCommand, error) {
	if len(args) == 0 {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("no command provided")}
	}

	op := args[0]
	if op != "install" {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported pip command: %s", op)}
	}

	cmd := &InstallCommand{
		Ecosystem:      "pypi",
		PackageManager: "pip",
		RawCommand:     args,
		Operation:      op,
	}

	var packageSpecs []string
	i := 1
	for i < len(args) {
		arg := args[i]
		if arg == "-r" || arg == "--requirement" {
			if i+1 < len(args) {
				cmd.DependencyFiles = append(cmd.DependencyFiles, args[i+1])
				i += 2
			} else {
				return nil, InterceptError{Code: ExitUsageError, Err: fmt.Errorf("missing argument for %s", arg)}
			}
		} else if strings.HasPrefix(arg, "-") {
			cmd.Flags = append(cmd.Flags, arg)
			// Check for advanced flags that are unsupported
			if arg == "--index-url" || arg == "--extra-index-url" || arg == "-e" || arg == "--editable" {
				return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported advanced pip flag: %s", arg)}
			}
			// If it's a flag that requires a value, skip next if not a flag
			if flagRequiresValue(arg) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd.Flags = append(cmd.Flags, args[i+1])
				i += 2
			} else {
				i++
			}
		} else {
			// Check for advanced unsupported inputs (local paths, editable, URLs, wheel files)
			if isUnsupportedPipInput(arg) {
				return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported advanced pip input: %s", arg)}
			}
			packageSpecs = append(packageSpecs, arg)
			i++
		}
	}

	for _, spec := range packageSpecs {
		name, specifier, exact := parsePipSpec(spec)
		cmd.Packages = append(cmd.Packages, PackageRequest{
			Name:             name,
			VersionSpecifier: specifier,
			ExactVersion:     exact,
			IsDirect:         true,
			Source:           "pypi",
		})
	}

	return cmd, nil
}

func flagRequiresValue(flag string) bool {
	switch flag {
	case "-c", "--constraint", "-e", "--editable", "-t", "--target", "--platform",
		"--python-version", "--implementation", "--abi", "--root", "--prefix",
		"-b", "--build", "--src", "--upgrade-strategy", "--install-option",
		"--global-option", "--install-headers", "--keyring-provider", "--index-url",
		"--extra-index-url", "--log", "--proxy", "--retries", "--timeout",
		"--exists-action", "--trusted-host", "--cert", "--client-cert",
		"--cache-dir", "--checksum":
		return true
	default:
		return false
	}
}

func isUnsupportedPipInput(s string) bool {
	sLower := strings.ToLower(s)
	// git/vcs protocols
	if strings.HasPrefix(sLower, "git+") || strings.HasPrefix(sLower, "hg+") ||
		strings.HasPrefix(sLower, "svn+") || strings.HasPrefix(sLower, "bzr+") {
		return true
	}
	// URLs
	if strings.HasPrefix(sLower, "http://") || strings.HasPrefix(sLower, "https://") {
		return true
	}
	// local path references
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	// archives / wheels
	if strings.HasSuffix(sLower, ".whl") || strings.HasSuffix(sLower, ".tar.gz") ||
		strings.HasSuffix(sLower, ".zip") || strings.HasSuffix(sLower, ".tgz") {
		return true
	}
	return false
}

func parsePipSpec(spec string) (string, string, string) {
	// Operators: ==, >=, <=, >, <, !=, ~=, ===
	operators := []string{"===", "==", ">=", "<=", "!=", "~=", ">", "<"}
	for _, op := range operators {
		if idx := strings.Index(spec, op); idx != -1 {
			name := strings.TrimSpace(spec[:idx])
			specifier := spec[idx:]
			exact := ""
			if op == "==" {
				exact = strings.TrimSpace(spec[idx+len(op):])
				// Clean any surrounding quotes
				exact = strings.Trim(exact, `"'`)
			}
			// Clean name/specifier from potential quotes if passed in quotes
			name = strings.Trim(name, `"'`)
			specifier = strings.Trim(specifier, `"'`)
			return name, specifier, exact
		}
	}
	return strings.Trim(spec, `"'`), "", ""
}
