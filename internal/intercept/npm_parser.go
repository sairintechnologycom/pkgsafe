package intercept

import (
	"fmt"
	"strings"
)

func ParseNPM(args []string) (*InstallCommand, error) {
	if len(args) == 0 {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("no command provided")}
	}

	op := args[0]
	if op != "install" && op != "i" && op != "add" && op != "ci" {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported npm command: %s", op)}
	}

	cmd := &InstallCommand{
		Ecosystem:      "npm",
		PackageManager: "npm",
		RawCommand:     args,
		Operation:      op,
	}

	if op == "ci" {
		cmd.IsCIInstall = true
		cmd.DependencyFiles = []string{"package-lock.json"}
		// Parse any flags passed to npm ci
		for _, arg := range args[1:] {
			if strings.HasPrefix(arg, "-") {
				cmd.Flags = append(cmd.Flags, arg)
			} else {
				cmd.UnknownArgs = append(cmd.UnknownArgs, arg)
			}
		}
		return cmd, nil
	}

	// For install, i, add:
	isDev := false
	var packageSpecs []string

	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			cmd.Flags = append(cmd.Flags, arg)
			if arg == "--save-dev" || arg == "-D" {
				isDev = true
			}
		} else {
			// Check for advanced unsupported inputs: local paths, tarballs, git URLs
			if isUnsupportedNPMInput(arg) {
				return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported advanced npm input: %s", arg)}
			}
			packageSpecs = append(packageSpecs, arg)
		}
	}

	if len(packageSpecs) == 0 {
		cmd.IsProjectInstall = true
		cmd.DependencyFiles = []string{"package.json"}
		// Also add package-lock.json if it exists (checked during execution)
	} else {
		for _, spec := range packageSpecs {
			name, ver := splitPackageSpec(spec)
			cmd.Packages = append(cmd.Packages, PackageRequest{
				Name:             name,
				VersionSpecifier: ver,
				ExactVersion:     ver, // npm exact version is usually just specified by version
				IsDevDependency:  isDev,
				IsDirect:         true,
				Source:           "registry",
			})
		}
	}

	return cmd, nil
}

func isUnsupportedNPMInput(s string) bool {
	// git URLs, local file paths, HTTP URLs, tarballs
	sLower := strings.ToLower(s)
	if strings.HasPrefix(sLower, "git+") || strings.HasPrefix(sLower, "git:") || strings.HasPrefix(sLower, "ssh:") {
		return true
	}
	if strings.HasPrefix(sLower, "http://") || strings.HasPrefix(sLower, "https://") {
		return true
	}
	if strings.HasSuffix(sLower, ".tgz") || strings.HasSuffix(sLower, ".tar.gz") {
		return true
	}
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	return false
}

func splitPackageSpec(s string) (string, string) {
	if strings.HasPrefix(s, "@") {
		idx := strings.LastIndex(s, "@")
		if idx > 0 {
			return s[:idx], s[idx+1:]
		}
		return s, ""
	}
	parts := strings.SplitN(s, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return s, ""
}
