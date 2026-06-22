package agent

import (
	"strings"
)

// Alternative represents a recommended alternative package.
type Alternative struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

var curatedAlternatives = map[string][]Alternative{
	"react-markdown-renderer-plus": {
		{Name: "react-markdown", Reason: "Established package with stronger ecosystem reputation"},
		{Name: "markdown-it", Reason: "Mature markdown parser with broad usage"},
	},
	"request-promise-native-plus": {
		{Name: "axios", Reason: "Established package with stronger ecosystem reputation"},
		{Name: "got", Reason: "Feature-rich and widely adopted HTTP client"},
		{Name: "undici", Reason: "Modern, fast HTTP/1.1 client for Node.js"},
	},
	"next-auth-mongodb-adapter-pro": {
		{Name: "@auth/mongodb-adapter", Reason: "Official MongoDB adapter for Auth.js/NextAuth.js"},
	},
}

// GetSafeAlternatives returns a list of curated or heuristic safe alternatives for a package.
func GetSafeAlternatives(requestedPackage string) []Alternative {
	req := strings.ToLower(strings.TrimSpace(requestedPackage))
	if alts, ok := curatedAlternatives[req]; ok {
		return alts
	}

	// Dynamic heuristic: if the package ends with one of the squatting suffixes,
	// suggest the base package without the suffix.
	for _, s := range suffixes {
		for _, sep := range []string{"-", "_", "."} {
			suffixPattern := sep + s
			if strings.HasSuffix(req, suffixPattern) {
				base := strings.TrimSuffix(req, suffixPattern)
				if base != "" {
					return []Alternative{
						{
							Name:   base,
							Reason: "Official or more established base package without suffix",
						},
					}
				}
			}
		}
	}

	return nil
}
