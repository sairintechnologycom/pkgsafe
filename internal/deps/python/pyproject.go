package python

import (
	"os"
	"strings"
)

func ParsePyprojectFile(path string) ([]Dependency, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var deps []Dependency
	raw := string(b)
	section := ""
	inArray := false
	for _, originalLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(stripInlineComment(originalLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			inArray = false
			continue
		}
		if section == "project" && strings.HasPrefix(line, "dependencies") {
			if strings.Contains(line, "[") && !strings.Contains(line, "]") {
				inArray = true
				continue
			}
			deps = append(deps, depsFromArrayLine(line, path)...)
			continue
		}
		if (section == "project" || strings.HasPrefix(section, "project.optional-dependencies")) && inArray {
			if strings.Contains(line, "]") {
				inArray = false
			}
			deps = append(deps, depsFromQuotedLine(line, path)...)
			continue
		}
		if section == "project.optional-dependencies" && strings.Contains(line, "[") {
			inArray = !strings.Contains(line, "]")
			deps = append(deps, depsFromArrayLine(line, path)...)
			continue
		}
		if section == "tool.poetry.dependencies" || strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies") {
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			name := strings.TrimSpace(key)
			if name == "python" {
				continue
			}
			spec := strings.Trim(strings.TrimSpace(val), `"'`)
			dep := ParseRequirementSpec(name + specifierForPoetry(spec))
			if dep.Name != "" {
				dep.SourceFile = path
				deps = append(deps, dep)
			}
		}
	}
	return deps, nil
}

func depsFromArrayLine(line, path string) []Dependency {
	if idx := strings.Index(line, "["); idx >= 0 {
		line = line[idx+1:]
	}
	return depsFromQuotedLine(line, path)
}

func depsFromQuotedLine(line, path string) []Dependency {
	var deps []Dependency
	for {
		start := strings.IndexAny(line, `"'`)
		if start < 0 {
			break
		}
		quote := line[start]
		rest := line[start+1:]
		end := strings.IndexByte(rest, quote)
		if end < 0 {
			break
		}
		spec := rest[:end]
		dep := ParseRequirementSpec(spec)
		if dep.Name != "" {
			dep.SourceFile = path
			deps = append(deps, dep)
		}
		line = rest[end+1:]
	}
	return deps
}

func specifierForPoetry(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return ""
	}
	if strings.HasPrefix(spec, "^") {
		return ">=" + strings.TrimPrefix(spec, "^")
	}
	if strings.HasPrefix(spec, "~") {
		return "~=" + strings.TrimLeft(spec, "~")
	}
	if strings.ContainsAny(spec, "<>!=") {
		return spec
	}
	return "==" + spec
}
