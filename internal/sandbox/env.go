package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// CleanEnv cleans the environment for sandbox execution.
// It implements a strict environment allowlist to prevent leakage of credentials
// or host directories into the sandboxed process.
func CleanEnv(sandboxRoot string) []string {
	var env []string

	// Strict list of allowed variable names
	allowed := map[string]bool{
		"PATH":     true,
		"LANG":     true,
		"LC_ALL":   true,
		"TERM":     true,
		"NODE_ENV": true,
	}

	// Dynamic blacklist keywords (drop anything containing these, even if allowed/part of allowed)
	dropKeywords := []string{
		"KEY",
		"TOKEN",
		"SECRET",
		"PASSWORD",
		"CREDENTIAL",
		"SESSION",
		"COOKIE",
		"AUTH",
	}

	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := parts[0]
		v := parts[1]

		kUpper := strings.ToUpper(k)
		if !allowed[kUpper] {
			continue
		}

		// Drop if key contains any sensitive keywords
		shouldDrop := false
		for _, kw := range dropKeywords {
			if strings.Contains(kUpper, kw) {
				shouldDrop = true
				break
			}
		}
		if shouldDrop {
			continue
		}

		// Explicit NODE_ENV safety check
		if kUpper == "NODE_ENV" {
			vLower := strings.ToLower(v)
			if vLower != "production" && vLower != "development" && vLower != "test" && vLower != "dev" && vLower != "prod" {
				continue
			}
		}

		env = append(env, e)
	}

	absRoot, err := filepath.Abs(sandboxRoot)
	if err != nil {
		absRoot = sandboxRoot
	}

	// Enforce redirection of home/profile, temporary, and XDG directories to the sandbox container path
	env = append(env,
		"HOME="+filepath.Join(absRoot, "home"),
		"USERPROFILE="+filepath.Join(absRoot, "home"),
		"TMPDIR="+filepath.Join(absRoot, "tmp"),
		"TEMP="+filepath.Join(absRoot, "tmp"),
		"TMP="+filepath.Join(absRoot, "tmp"),
		"XDG_CONFIG_HOME="+filepath.Join(absRoot, "home", ".config"),
		"XDG_CACHE_HOME="+filepath.Join(absRoot, "home", ".cache"),
		"XDG_DATA_HOME="+filepath.Join(absRoot, "home", ".local", "share"),
	)

	return env
}
