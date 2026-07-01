package python

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func ParsePoetryLockFile(path string) ([]Dependency, error) {
	return parseTOMLLockPackages(path)
}

func ParseUVLockFile(path string) ([]Dependency, error) {
	return parseTOMLLockPackages(path)
}

func ParsePipfile(path string) ([]Dependency, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var deps []Dependency
	section := ""
	for _, originalLine := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(stripInlineComment(originalLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if section != "packages" && section != "dev-packages" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name := strings.TrimSpace(strings.Trim(key, `"'`))
		spec := strings.TrimSpace(strings.Trim(val, `"'`))
		if strings.HasPrefix(spec, "{") {
			spec = valueFromInlineTable(spec, "version")
		}
		dep := ParseRequirementSpec(name + specifierForPipfile(spec))
		if dep.Name != "" {
			dep.SourceFile = path
			deps = append(deps, dep)
		}
	}
	return deps, nil
}

func ParsePipfileLock(path string) ([]Dependency, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock %q: %w", path, err)
	}
	var deps []Dependency
	for _, section := range []string{"default", "develop"} {
		for name, val := range raw[section] {
			spec := ""
			if entry, ok := val.(map[string]any); ok {
				if v, ok := entry["version"].(string); ok {
					spec = v
				}
			}
			dep := ParseRequirementSpec(name + specifierForPipfile(spec))
			if dep.Name != "" {
				dep.SourceFile = path
				deps = append(deps, dep)
			}
		}
	}
	return deps, nil
}

func ParseCondaEnvFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("conda environment.yml scanning is designed but not implemented in this milestone")
}

func parseTOMLLockPackages(path string) ([]Dependency, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var deps []Dependency
	inPackage := false
	name := ""
	version := ""
	flush := func() {
		if name == "" {
			return
		}
		dep := Dependency{Name: normalizeName(name), Version: version, Pinned: version != "", SourceFile: path}
		if version != "" {
			dep.Specifier = "==" + version
		}
		deps = append(deps, dep)
		name, version = "", ""
	}
	for _, originalLine := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(stripInlineComment(originalLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[package]]") {
			flush()
			inPackage = true
			continue
		}
		if !inPackage {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "name":
			name = strings.Trim(strings.TrimSpace(val), `"'`)
		case "version":
			version = strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	flush()
	return deps, nil
}

func specifierForPipfile(spec string) string {
	spec = strings.TrimSpace(strings.Trim(spec, `"'`))
	if spec == "" || spec == "*" {
		return ""
	}
	if strings.HasPrefix(spec, "==") || strings.ContainsAny(spec, "<>!=") {
		return spec
	}
	return "==" + spec
}

func valueFromInlineTable(raw, key string) string {
	raw = strings.Trim(strings.TrimSpace(raw), "{}")
	for _, part := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}
