package python

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Dependency struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Specifier  string `json:"specifier,omitempty"`
	Pinned     bool   `json:"pinned"`
	SourceFile string `json:"source_file,omitempty"`
}

func ParseFile(path string) ([]Dependency, error) {
	switch strings.ToLower(filepath.Base(path)) {
	case "requirements.txt":
		return ParseRequirementsFile(path)
	case "pyproject.toml":
		return ParsePyprojectFile(path)
	default:
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".txt" {
			return ParseRequirementsFile(path)
		}
		return nil, fmt.Errorf("unsupported Python dependency file %q", path)
	}
}

func ParseRequirementSpec(spec string) Dependency {
	spec = strings.TrimSpace(stripInlineComment(spec))
	spec = strings.Trim(spec, `"'`)
	if spec == "" {
		return Dependency{}
	}
	for _, marker := range []string{";", " #"} {
		if idx := strings.Index(spec, marker); idx >= 0 {
			spec = strings.TrimSpace(spec[:idx])
		}
	}
	namePart := spec
	version := ""
	specifier := ""
	for _, op := range []string{"===", "==", "~=", ">=", "<=", "!=", ">", "<"} {
		if idx := strings.Index(spec, op); idx > 0 {
			namePart = strings.TrimSpace(spec[:idx])
			specifier = strings.TrimSpace(spec[idx:])
			if op == "==" || op == "===" {
				version = strings.TrimSpace(strings.TrimPrefix(specifier, op))
				if cut := strings.IndexAny(version, ", "); cut >= 0 {
					version = version[:cut]
				}
			}
			break
		}
	}
	if idx := strings.Index(namePart, "["); idx >= 0 {
		namePart = namePart[:idx]
	}
	name := normalizeName(namePart)
	return Dependency{Name: name, Version: version, Specifier: specifier, Pinned: version != ""}
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func stripInlineComment(s string) string {
	inQuote := false
	var quote rune
	for i, r := range s {
		if (r == '\'' || r == '"') && (!inQuote || quote == r) {
			if inQuote {
				inQuote = false
			} else {
				inQuote = true
				quote = r
			}
		}
		if r == '#' && !inQuote {
			return s[:i]
		}
	}
	return s
}
