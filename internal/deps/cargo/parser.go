package cargo

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// Dependency represents a Cargo dependency.
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseCargoLock parses a Cargo.lock file content and extracts crate names and versions.
func ParseCargoLock(content []byte) ([]Dependency, error) {
	var deps []Dependency
	scanner := bufio.NewScanner(bytes.NewReader(content))

	var currentName string
	var currentVersion string
	inPackage := false

	nameRegex := regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	versionRegex := regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "[[package]]" {
			if inPackage && currentName != "" && currentVersion != "" {
				deps = append(deps, Dependency{
					Name:    currentName,
					Version: currentVersion,
				})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		// If we encounter another section header (e.g. [metadata] or [patch]) we end the current package block
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			if inPackage && currentName != "" && currentVersion != "" {
				deps = append(deps, Dependency{
					Name:    currentName,
					Version: currentVersion,
				})
			}
			inPackage = false
			currentName = ""
			currentVersion = ""
			continue
		}

		if inPackage {
			if matches := nameRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentName = matches[1]
			} else if matches := versionRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentVersion = matches[1]
			}
		}
	}

	// append the last package if any
	if inPackage && currentName != "" && currentVersion != "" {
		deps = append(deps, Dependency{
			Name:    currentName,
			Version: currentVersion,
		})
	}

	return deps, scanner.Err()
}
