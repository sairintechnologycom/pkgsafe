package registry

import (
	"net/url"
	"regexp"
)

func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		u.User = url.UserPassword("REDACTED", "REDACTED")
	}
	return u.String()
}

func RedactSecrets(input string) string {
	// Redact standard Auth header bearer tokens
	reBearer := regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/=]+`)
	input = reBearer.ReplaceAllString(input, "Bearer REDACTED")

	// Redact basic auth strings
	reBasic := regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9\-\._~\+\/=]+`)
	input = reBasic.ReplaceAllString(input, "Basic REDACTED")

	return input
}
