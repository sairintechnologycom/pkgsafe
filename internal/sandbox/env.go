package sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

var envBlacklist = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET",
	"AZURE_TENANT_ID",
	"AZURE_CLIENT_ID",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"NPM_TOKEN",
	"NODE_AUTH_TOKEN",
	"VAULT_TOKEN",
	"KUBECONFIG",
	"SSH_AUTH_SOCK",
	"HOME",
	"USERPROFILE",
	"TMPDIR",
	"TEMP",
	"TMP",
}

func CleanEnv(sandboxRoot string) []string {
	var env []string
	blacklistMap := make(map[string]bool)
	for _, k := range envBlacklist {
		blacklistMap[strings.ToUpper(k)] = true
	}

	// Blacklist generic secret keywords to block dynamically-named keys
	secretKeywords := []string{
		"SECRET", "TOKEN", "KEY", "PASSWORD", "PASS", "AUTH", "CREDENTIAL", "SIGNATURE", "PRIVATE", "JWT",
	}

	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) > 0 {
			k := strings.ToUpper(parts[0])
			if blacklistMap[k] {
				continue
			}
			// Skip dynamic secrets
			isSecret := false
			for _, kw := range secretKeywords {
				if strings.Contains(k, kw) {
					isSecret = true
					break
				}
			}
			if isSecret {
				continue
			}
		}
		env = append(env, e)
	}

	absRoot, err := filepath.Abs(sandboxRoot)
	if err != nil {
		absRoot = sandboxRoot
	}

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
