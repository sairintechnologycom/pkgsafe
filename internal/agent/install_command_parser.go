package agent

import (
	"errors"
	"strings"
)

// ParsedPackage represents a package name and version parsed from a command.
type ParsedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseInstallCommand parses an npm install/add command to extract package specs.
func ParseInstallCommand(command string) ([]ParsedPackage, error) {
	cmd := strings.TrimSpace(command)

	var rest string
	if strings.HasPrefix(cmd, "npm install ") {
		rest = strings.TrimPrefix(cmd, "npm install ")
	} else if strings.HasPrefix(cmd, "npm install") && len(cmd) == 11 {
		return nil, errors.New("no packages specified")
	} else if strings.HasPrefix(cmd, "npm i ") {
		rest = strings.TrimPrefix(cmd, "npm i ")
	} else if strings.HasPrefix(cmd, "npm i") && len(cmd) == 5 {
		return nil, errors.New("no packages specified")
	} else if strings.HasPrefix(cmd, "npm add ") {
		rest = strings.TrimPrefix(cmd, "npm add ")
	} else if strings.HasPrefix(cmd, "npm add") && len(cmd) == 7 {
		return nil, errors.New("no packages specified")
	} else {
		return nil, errors.New("unsupported or invalid install command")
	}

	fields := strings.Fields(rest)
	var packages []ParsedPackage
	for _, field := range fields {
		if strings.HasPrefix(field, "-") {
			// Skip flags like -D, --save-dev, -g, etc.
			continue
		}

		name, version := splitPackageSpec(field)
		if name == "" {
			continue
		}
		if version == "" {
			version = "latest"
		}
		packages = append(packages, ParsedPackage{
			Name:    name,
			Version: version,
		})
	}

	if len(packages) == 0 {
		return nil, errors.New("no packages found in the command")
	}

	return packages, nil
}

func splitPackageSpec(s string) (string, string) {
	if strings.HasPrefix(s, "@") {
		idx := strings.LastIndex(s, "@")
		if idx > 0 {
			return s[:idx], s[idx+1:]
		}
		return s, "latest"
	}
	parts := strings.SplitN(s, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return s, "latest"
}
