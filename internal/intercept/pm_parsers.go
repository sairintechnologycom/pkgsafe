package intercept

import (
	"fmt"
	"strings"
)

// ParsePnpm parses pnpm install/add/i/ci commands into the shared install model.
// Ecosystem remains npm; package manager is pnpm for binary resolution.
func ParsePnpm(args []string) (*InstallCommand, error) {
	return parseNodeFamily("pnpm", args, []string{"install", "i", "add", "ci"})
}

// ParseYarn parses yarn install/add commands (classic and modern CLI).
func ParseYarn(args []string) (*InstallCommand, error) {
	if len(args) == 0 {
		// bare `yarn` is a project install
		return &InstallCommand{
			Ecosystem:        "npm",
			PackageManager:   "yarn",
			RawCommand:       args,
			Operation:        "install",
			IsProjectInstall: true,
			DependencyFiles:  []string{"package.json"},
		}, nil
	}
	return parseNodeFamily("yarn", args, []string{"install", "add"})
}

// ParseUV parses uv package installs: `uv pip install …` and `uv add …`.
func ParseUV(args []string) (*InstallCommand, error) {
	if len(args) == 0 {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("no command provided")}
	}

	// uv pip install …
	if args[0] == "pip" {
		if len(args) < 2 {
			return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported uv pip command")}
		}
		cmd, err := ParsePip(args[1:])
		if err != nil {
			return nil, err
		}
		cmd.PackageManager = "uv"
		cmd.RawCommand = args
		return cmd, nil
	}

	// uv add pkg [pkg…]
	if args[0] == "add" {
		cmd := &InstallCommand{
			Ecosystem:      "pypi",
			PackageManager: "uv",
			RawCommand:     args,
			Operation:      "add",
		}
		for _, arg := range args[1:] {
			if strings.HasPrefix(arg, "-") {
				cmd.Flags = append(cmd.Flags, arg)
				continue
			}
			if isUnsupportedPipInput(arg) {
				return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported advanced uv input: %s", arg)}
			}
			name, specifier, exact := parsePipSpec(arg)
			cmd.Packages = append(cmd.Packages, PackageRequest{
				Name:             name,
				VersionSpecifier: specifier,
				ExactVersion:     exact,
				IsDirect:         true,
				Source:           "pypi",
			})
		}
		if len(cmd.Packages) == 0 {
			return nil, InterceptError{Code: ExitUsageError, Err: fmt.Errorf("uv add requires at least one package")}
		}
		return cmd, nil
	}

	// uv sync installs from lockfile — treat as project install for scanning.
	if args[0] == "sync" {
		return &InstallCommand{
			Ecosystem:        "pypi",
			PackageManager:   "uv",
			RawCommand:       args,
			Operation:        "sync",
			IsProjectInstall: true,
			DependencyFiles:  []string{"pyproject.toml", "uv.lock", "requirements.txt"},
		}, nil
	}

	return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported uv command: %s", args[0])}
}

func parseNodeFamily(pm string, args []string, ops []string) (*InstallCommand, error) {
	if len(args) == 0 {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("no command provided")}
	}

	op := args[0]
	allowed := false
	for _, candidate := range ops {
		if op == candidate {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, InterceptError{Code: ExitUnsupportedCommand, Err: fmt.Errorf("unsupported %s command: %s", pm, op)}
	}

	// Reuse npm install parsing for package extraction, then rebrand manager.
	npmArgs := args
	// yarn/pnpm use `add` which npm parser already accepts.
	cmd, err := ParseNPM(npmArgs)
	if err != nil {
		return nil, err
	}
	cmd.PackageManager = pm
	cmd.RawCommand = args

	// Prefer ecosystem lockfiles when project install.
	if cmd.IsProjectInstall || cmd.IsCIInstall {
		switch pm {
		case "pnpm":
			cmd.DependencyFiles = []string{"package.json", "pnpm-lock.yaml"}
		case "yarn":
			cmd.DependencyFiles = []string{"package.json", "yarn.lock"}
		}
	}
	return cmd, nil
}
