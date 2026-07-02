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
		gitURL := ""
		if strings.HasPrefix(spec, "{") {
			gitURL = valueFromInlineTable(spec, "git")
			spec = valueFromInlineTable(spec, "version")
		}
		dep := ParseRequirementSpec(name + specifierForPipfile(spec))
		if dep.Name != "" {
			dep.SourceFile = path
			dep.DirectURL = gitURL
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
	indexURLs := pipfileLockSources(raw["_meta"])
	var deps []Dependency
	for _, section := range []string{"default", "develop"} {
		for name, val := range raw[section] {
			spec := ""
			var hashes []string
			registry := ""
			directURL := ""
			if entry, ok := val.(map[string]any); ok {
				if v, ok := entry["version"].(string); ok {
					spec = v
				}
				if hs, ok := entry["hashes"].([]any); ok {
					for _, h := range hs {
						if s, ok := h.(string); ok {
							hashes = append(hashes, s)
						}
					}
				}
				if idx, ok := entry["index"].(string); ok {
					registry = indexURLs[idx]
					if registry == "" {
						registry = idx
					}
				}
				if git, ok := entry["git"].(string); ok {
					directURL = git
				}
			}
			dep := ParseRequirementSpec(name + specifierForPipfile(spec))
			if dep.Name != "" {
				dep.SourceFile = path
				dep.Hashes = hashes
				dep.Registry = registry
				dep.DirectURL = directURL
				dep.FromLockfile = true
				deps = append(deps, dep)
			}
		}
	}
	return deps, nil
}

// pipfileLockSources maps Pipfile.lock _meta source names to their URLs.
func pipfileLockSources(meta map[string]any) map[string]string {
	out := map[string]string{}
	if meta == nil {
		return out
	}
	sources, ok := meta["sources"].([]any)
	if !ok {
		return out
	}
	for _, s := range sources {
		entry, ok := s.(map[string]any)
		if !ok {
			continue
		}
		name, _ := entry["name"].(string)
		url, _ := entry["url"].(string)
		if name != "" && url != "" {
			out[name] = url
		}
	}
	return out
}

func ParseCondaEnvFile(path string) ([]Dependency, error) {
	return nil, fmt.Errorf("conda environment.yml scanning is designed but not implemented in this milestone")
}

// parseTOMLLockPackages reads [[package]] entries from poetry.lock and
// uv.lock. It tracks the current TOML table so keys inside sub-tables such as
// [package.dependencies] or [package.source] cannot clobber the package's own
// name/version, records artifact hashes (poetry `files`, uv `wheels`/`sdist`),
// and captures the explicit registry or local/direct source when one is named.
func parseTOMLLockPackages(path string) ([]Dependency, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var deps []Dependency
	table := ""
	cur := Dependency{}
	inPackage := false
	arrayKey := ""
	sourceType, sourceRef := "", ""
	flush := func() {
		if !inPackage || cur.Name == "" {
			return
		}
		dep := cur
		switch sourceType {
		case "":
		case "legacy", "registry":
			dep.Registry = sourceRef
		case "git", "url":
			dep.DirectURL = sourceRef
		default:
			// virtual/editable/path/directory/file: the project itself or a
			// local artifact — not a registry package.
			dep.LocalSource = true
		}
		if dep.Version != "" {
			dep.Specifier = "==" + dep.Version
			dep.Pinned = true
		}
		dep.FromLockfile = true
		dep.SourceFile = path
		deps = append(deps, dep)
	}
	reset := func() {
		cur = Dependency{}
		sourceType, sourceRef = "", ""
		arrayKey = ""
	}
	for _, originalLine := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(stripInlineComment(originalLine))
		if line == "" {
			continue
		}
		if arrayKey != "" {
			// Inside a multi-line array (poetry files = [...], uv wheels = [...]).
			if h := valueFromInlineTable(strings.Trim(line, ","), "hash"); h != "" {
				cur.Hashes = append(cur.Hashes, h)
			}
			if line == "]" || strings.HasSuffix(line, "]") {
				arrayKey = ""
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			header := strings.Trim(line, "[]")
			if header == "package" {
				flush()
				reset()
				inPackage = true
				table = "package"
				continue
			}
			if inPackage && strings.HasPrefix(header, "package.") {
				table = header
				continue
			}
			// Any unrelated top-level table ends the current package.
			flush()
			reset()
			inPackage = false
			table = header
			continue
		}
		if !inPackage {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k := strings.TrimSpace(key)
		v := strings.TrimSpace(val)
		switch table {
		case "package":
			switch k {
			case "name":
				cur.Name = normalizeName(strings.Trim(v, `"'`))
			case "version":
				cur.Version = strings.Trim(v, `"'`)
			case "source":
				// uv.lock inline table: { registry = "..." } / { virtual = "." } / ...
				for _, t := range []string{"registry", "virtual", "editable", "path", "directory", "git", "url"} {
					if ref := valueFromInlineTable(v, t); ref != "" {
						sourceType, sourceRef = t, ref
						break
					}
				}
			case "sdist":
				if h := valueFromInlineTable(v, "hash"); h != "" {
					cur.Hashes = append(cur.Hashes, h)
				}
			case "files", "wheels":
				if strings.HasSuffix(v, "[") {
					arrayKey = k
				}
			}
		case "package.source":
			// poetry.lock sub-table: type = "legacy", url = "...".
			switch k {
			case "type":
				sourceType = strings.Trim(v, `"'`)
			case "url", "reference":
				if sourceRef == "" || k == "url" {
					sourceRef = strings.Trim(v, `"'`)
				}
			}
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
