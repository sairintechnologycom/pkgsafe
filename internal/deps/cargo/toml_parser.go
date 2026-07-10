package cargo

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// ParseCargoToml parses a Cargo.toml file and extracts dependency names and versions
// from [dependencies], [dev-dependencies], and [build-dependencies] sections.
func ParseCargoToml(content []byte) ([]Dependency, error) {
	var deps []Dependency

	inDeps := false
	scanner := bufio.NewScanner(bytes.NewReader(content))

	// Regex patterns for reliable key-value matching
	sectionRegex := regexp.MustCompile(`^\[(dependencies|dev-dependencies|build-dependencies)\]`)
	newSectionRegex := regexp.MustCompile(`^\[`)
	// Matches:  name = "1.2.3"
	simpleVersionRegex := regexp.MustCompile(`^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"`)
	// Matches: name = { version = "1.2.3", ... }
	inlineTableRegex := regexp.MustCompile(`^([A-Za-z0-9_\-]+)\s*=\s*\{`)
	versionInTableRegex := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if sectionRegex.MatchString(line) {
			inDeps = true
			continue
		}
		if inDeps && newSectionRegex.MatchString(line) {
			inDeps = false
			continue
		}

		if !inDeps {
			continue
		}

		// Try simple string form: name = "version"
		if m := simpleVersionRegex.FindStringSubmatch(line); len(m) == 3 {
			deps = append(deps, Dependency{
				Name:    m[1],
				Version: m[2],
			})
			continue
		}

		// Try inline table form: name = { version = "...", ... }
		if m := inlineTableRegex.FindStringSubmatch(line); len(m) >= 2 {
			name := m[1]
			version := "latest"
			if vm := versionInTableRegex.FindStringSubmatch(line); len(vm) == 2 {
				version = vm[1]
			}
			deps = append(deps, Dependency{
				Name:    name,
				Version: version,
			})
			continue
		}
	}

	return deps, scanner.Err()
}
