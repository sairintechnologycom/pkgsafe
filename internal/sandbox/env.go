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

	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) > 0 {
			k := strings.ToUpper(parts[0])
			if blacklistMap[k] {
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
	)
	return env
}
