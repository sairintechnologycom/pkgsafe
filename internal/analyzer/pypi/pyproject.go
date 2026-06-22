package pypi

import (
	"strings"
)

func BuildBackend(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "build-backend") {
			_, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			return strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	return ""
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
