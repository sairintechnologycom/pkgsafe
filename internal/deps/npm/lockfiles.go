package npm

import (
	"bufio"
	"bytes"
	"strings"
)

// LockfileDependency represents a single package parsed from a yarn or pnpm lockfile.
type LockfileDependency struct {
	Name    string
	Version string
}

// ParseYarnLock parses a yarn.lock file and extracts package names and resolved versions.
func ParseYarnLock(content []byte) ([]LockfileDependency, error) {
	var deps []LockfileDependency

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var currentNames []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// A header line ends with ":" and lists one or more package specifiers
		// e.g.:  "lodash@^4.0.0, lodash@^4.17.0":
		if strings.HasSuffix(line, ":") {
			currentNames = nil
			header := strings.TrimSuffix(line, ":")
			// Strip surrounding quotes (yarn v2+ wraps headers in quotes)
			header = strings.Trim(header, `"'`)
			parts := strings.Split(header, ",")
			for _, part := range parts {
				part = strings.Trim(strings.TrimSpace(part), `"'`)
				// Remove the version range after the last "@" to get the package name
				idx := strings.LastIndex(part, "@")
				if idx > 0 {
					currentNames = append(currentNames, part[:idx])
				} else if part != "" {
					currentNames = append(currentNames, part)
				}
			}
			continue
		}

		// "  version ..." lines give the resolved version for the current block
		if strings.HasPrefix(line, "version ") {
			version := strings.Trim(strings.TrimPrefix(line, "version "), `"'`)
			for _, name := range currentNames {
				deps = append(deps, LockfileDependency{Name: name, Version: version})
			}
			// Reset after capturing version (one version per block)
			currentNames = nil
		}
	}

	return deps, scanner.Err()
}

// ParsePnpmLock parses a pnpm-lock.yaml file and extracts package names and versions.
// It handles both pnpm v5/v6 (slash-prefixed keys) and v8+ ("pkg@ver:" keys).
func ParsePnpmLock(content []byte) ([]LockfileDependency, error) {
	var deps []LockfileDependency
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Only package-level keys have the form:  /name@version: or 'name@version':
		if (!strings.HasPrefix(line, "/") && !strings.Contains(line, "@")) || !strings.HasSuffix(line, ":") {
			continue
		}

		line = strings.TrimSuffix(line, ":")
		line = strings.Trim(line, `'"`)
		if strings.HasPrefix(line, "/") {
			line = line[1:]
		}

		// Find last "@" to split name and version
		idx := strings.LastIndex(line, "@")
		if idx <= 0 {
			// Fallback: split on last "/"
			idx = strings.LastIndex(line, "/")
			if idx <= 0 {
				continue
			}
			name := line[:idx]
			version := line[idx+1:]
			key := name + "@" + version
			if !seen[key] {
				seen[key] = true
				deps = append(deps, LockfileDependency{Name: name, Version: version})
			}
			continue
		}

		name := line[:idx]
		version := line[idx+1:]
		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			deps = append(deps, LockfileDependency{Name: name, Version: version})
		}
	}

	return deps, scanner.Err()
}
