package pypi

import (
	"strings"
)

// BuildSystem is the parsed [build-system] table of a pyproject.toml.
type BuildSystem struct {
	Backend string
	// BackendPath holds backend-path entries. A non-empty value means the
	// build backend is loaded from code shipped inside the package itself
	// (PEP 517 in-tree backend), which runs arbitrary project code at build
	// time regardless of what backend name is declared.
	BackendPath []string
	Requires    []string
}

// ParseBuildSystem reads the [build-system] table section-aware, so keys with
// the same names in other tables (tool config, examples embedded in strings)
// are not picked up.
func ParseBuildSystem(raw string) BuildSystem {
	var bs BuildSystem
	section := ""
	arrayKey := ""
	for _, originalLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(originalLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if arrayKey != "" {
			bs.appendArrayValues(arrayKey, line)
			if strings.Contains(line, "]") {
				arrayKey = ""
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		if section != "build-system" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k := strings.TrimSpace(key)
		v := strings.TrimSpace(val)
		switch k {
		case "build-backend":
			bs.Backend = strings.Trim(v, `"'`)
		case "backend-path", "requires":
			if strings.HasPrefix(v, "[") && !strings.Contains(v, "]") {
				arrayKey = k
				continue
			}
			bs.appendArrayValues(k, v)
		}
	}
	return bs
}

func (bs *BuildSystem) appendArrayValues(key, line string) {
	for _, v := range quotedValues(line) {
		switch key {
		case "backend-path":
			bs.BackendPath = append(bs.BackendPath, v)
		case "requires":
			bs.Requires = append(bs.Requires, v)
		}
	}
}

func quotedValues(line string) []string {
	var out []string
	for {
		start := strings.IndexAny(line, `"'`)
		if start < 0 {
			return out
		}
		quote := line[start]
		rest := line[start+1:]
		end := strings.IndexByte(rest, quote)
		if end < 0 {
			return out
		}
		if v := strings.TrimSpace(rest[:end]); v != "" {
			out = append(out, v)
		}
		line = rest[end+1:]
	}
}

// DirectBuildRequirement reports whether a [build-system] requires entry is a
// direct URL or VCS reference rather than an index-resolved requirement.
func DirectBuildRequirement(req string) bool {
	return strings.Contains(req, "://") || strings.Contains(req, "git+")
}

func UnknownBuildBackend(backend string) bool {
	backend = strings.ToLower(strings.TrimSpace(backend))
	if backend == "" {
		return false
	}
	known := []string{
		"setuptools.build_meta",
		"setuptools.build_meta:__legacy__",
		"hatchling.build",
		"flit_core.buildapi",
		"poetry.core.masonry.api",
		"pdm.backend",
		"maturin",
		"mesonpy",
		"scikit_build_core.build",
	}
	for _, k := range known {
		if backend == k || strings.HasPrefix(backend, k+".") {
			return false
		}
	}
	return true
}
