package intercept

import (
	"regexp"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/registry"
)

var (
	secretParamRegex = regexp.MustCompile(`(?i)(token|password|_auth|key|secret|pass|auth|reason)(?:=|\s+)([^/ \t\n\r]+)`)
	urlAuthRegex     = regexp.MustCompile(`(?i)(https?://)([^/ \t\n\r]+:[^/ \t\n\r]+@)`)
)

func RedactCommand(cmd []string) []string {
	redacted := make([]string, len(cmd))
	for i := 0; i < len(cmd); i++ {
		arg := cmd[i]
		if i > 0 {
			prev := cmd[i-1]
			prevLower := strings.ToLower(prev)
			isPrevSecretKey := strings.HasPrefix(prev, "-") && (strings.Contains(prevLower, "token") || strings.Contains(prevLower, "password") ||
				strings.Contains(prevLower, "_auth") || strings.Contains(prevLower, "key") ||
				strings.Contains(prevLower, "secret") || strings.Contains(prevLower, "pass") ||
				strings.Contains(prevLower, "auth") || strings.Contains(prevLower, "reason") || prev == "-t")
			if isPrevSecretKey && !strings.Contains(prev, "=") {
				redacted[i] = "[REDACTED]"
				continue
			}
		}
		redacted[i] = RedactString(arg)
	}
	return redacted
}

func RedactString(s string) string {
	// First redact generic tokens (ghp_, npm_, sk_, AWS, PEM, basic auth URL)
	s = registry.RedactSecrets(s)

	s = urlAuthRegex.ReplaceAllString(s, "$1[REDACTED]@")
	return secretParamRegex.ReplaceAllStringFunc(s, func(match string) string {
		if strings.Contains(match, "=") {
			parts := strings.SplitN(match, "=", 2)
			return parts[0] + "=[REDACTED]"
		}
		parts := strings.Fields(match)
		if len(parts) >= 2 {
			return parts[0] + " [REDACTED]"
		}
		return "[REDACTED]"
	})
}
