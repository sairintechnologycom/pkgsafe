package policy

import "strings"

type Mode string

const (
	ModeWarn  Mode = "warn"
	ModeBlock Mode = "block"
	ModeAudit Mode = "audit"
)

type Policy struct {
	Mode           Mode
	ProtectedPaths []string
	BlockPatterns  []string
	WarnPatterns   []string
}

func Default() Policy {
	return Policy{
		Mode: ModeWarn,
		ProtectedPaths: []string{
			"~/.aws", "~/.azure", "~/.gcp", "~/.ssh", "~/.kube", "~/.docker",
			"~/.npmrc", "~/.pypirc", ".env", ".env.local", ".github", ".vault-token",
		},
		BlockPatterns: []string{
			"~/.aws", "~/.ssh", "~/.npmrc", ".env", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
			"VAULT_TOKEN", "GITHUB_TOKEN", "id_rsa", "credentials", ".npmrc", ".aws", ".ssh", ".kube",
			"token", "secret",
		},
		WarnPatterns: []string{
			"curl", "wget", "Invoke-WebRequest", "base64", "eval", "child_process", "netcat", " nc ",
			"powershell", "bash -c", "sh -c", "http://", "https://",
		},
	}
}

func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block":
		return ModeBlock
	case "audit":
		return ModeAudit
	default:
		return ModeWarn
	}
}
