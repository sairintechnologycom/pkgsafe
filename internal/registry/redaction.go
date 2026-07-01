package registry

import (
	"net/url"
	"os"
	"regexp"
	"strings"
)

// RedactURL redacts username and password from registry URLs
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback to regex if parsing fails
		reURLBasicAuth := regexp.MustCompile(`(?i)(https?://)([^:@/ \t\n\r]+):([^@/ \t\n\r]+)(@)`)
		redacted := reURLBasicAuth.ReplaceAllString(rawURL, "$1REDACTED:REDACTED$4")
		return redactURLQuerySecrets(redacted)
	}
	if u.User != nil {
		u.User = url.UserPassword("REDACTED", "REDACTED")
	}
	q := u.Query()
	for key := range q {
		if isSecretKey(key) {
			q.Set(key, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// RedactSecrets scans input content and replaces sensitive patterns/tokens with placeholders
func RedactSecrets(input string) string {
	// 1. Redact basic auth URLs
	reURLBasicAuth := regexp.MustCompile(`(?i)(https?://)([^:@/ \t\n\r]+):([^@/ \t\n\r]+)(@)`)
	input = reURLBasicAuth.ReplaceAllString(input, "${1}REDACTED:REDACTED${4}")
	input = redactURLQuerySecrets(input)

	// 2. Redact standard Auth header bearer tokens
	reBearer := regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/=]+`)
	input = reBearer.ReplaceAllString(input, "Bearer REDACTED")

	// 3. Redact basic auth strings
	reBasic := regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9\-\._~\+\/=]+`)
	input = reBasic.ReplaceAllString(input, "Basic REDACTED")

	// 4. GitHub tokens (ghp_..., github_pat_...)
	reGitHub := regexp.MustCompile(`(?i)\b(ghp_[A-Za-z0-9_]{16,255}|github_pat_[A-Za-z0-9_]{30,255})\b`)
	input = reGitHub.ReplaceAllString(input, "[REDACTED]")

	// 5. NPM tokens (npm_...)
	reNPM := regexp.MustCompile(`(?i)\bnpm_[A-Za-z0-9_]{16,255}\b`)
	input = reNPM.ReplaceAllString(input, "[REDACTED]")

	// 6. Stripe secrets (sk_test_..., sk_live_..., sk-test-..., sk-live-...)
	reStripe := regexp.MustCompile(`(?i)\bsk[_-](?:test|live)[_-][A-Za-z0-9_]{16,255}\b`)
	input = reStripe.ReplaceAllString(input, "[REDACTED]")

	// 7. AWS access keys (AKIA..., ASIA...)
	reAWS := regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)
	input = reAWS.ReplaceAllString(input, "[REDACTED]")

	// 8. Private Key PEM block
	rePEM := regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	input = rePEM.ReplaceAllString(input, "[REDACTED]")

	// 9. Dynamic environment variables redaction
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := parts[0]
		v := parts[1]
		if len(v) < 6 { // don't redact short values like "true", "yes", etc.
			continue
		}
		kUpper := strings.ToUpper(k)
		isSecret := false
		for _, kw := range []string{"TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH", "COOKIE", "SESSION", "CREDENTIAL"} {
			if strings.Contains(kUpper, kw) {
				isSecret = true
				break
			}
		}
		if isSecret {
			input = strings.ReplaceAll(input, v, "[REDACTED]")
		}
	}

	return input
}

func redactURLQuerySecrets(input string) string {
	reQuerySecret := regexp.MustCompile(`(?i)([?&][^=\s&]*(?:token|key|secret|password|auth|credential)[^=\s&]*=)[^&\s]+`)
	return reQuerySecret.ReplaceAllString(input, "${1}REDACTED")
}

func isSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, word := range []string{"token", "key", "secret", "password", "auth", "credential"} {
		if strings.Contains(k, word) {
			return true
		}
	}
	return false
}
