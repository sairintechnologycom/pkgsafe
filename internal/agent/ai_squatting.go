package agent

import (
	"strings"
)

var suffixes = []string{
	"plus", "pro", "advanced", "enhanced", "adapter", "integration",
	"connector", "official", "secure", "enterprise",
}

var frameworkNames = []string{
	"react", "vue", "angular", "axios", "lodash", "express", "next", "vite", "webpack", "typescript",
	"eslint", "prettier", "jest", "mocha", "chalk", "commander", "yargs", "moment", "dayjs", "uuid",
	"mongoose", "sequelize", "nestjs", "redux", "rxjs", "tailwindcss", "socket.io", "dotenv", "debug", "glob",
	"npm", "node", "js",
}

// CheckAISquatting runs heuristics to determine if a package is a likely AI package squatting candidate.
func CheckAISquatting(name string, description string, repository any, hasScripts bool, ageDays int) bool {
	lowerName := strings.ToLower(name)

	// Signal 2 & 7: Resembles popular framework/package name and has generic suffixes
	hasSuffix := false
	for _, s := range suffixes {
		if strings.HasSuffix(lowerName, "-"+s) || strings.HasSuffix(lowerName, "_"+s) || strings.HasSuffix(lowerName, "."+s) || strings.HasSuffix(lowerName, s) {
			hasSuffix = true
			break
		}
	}

	hasFramework := false
	for _, f := range frameworkNames {
		if strings.Contains(lowerName, f) {
			hasFramework = true
			break
		}
	}

	isSquattingPattern := hasSuffix && hasFramework

	// Count other suspicious signals
	signals := 0

	// Signal 1: Package name is long and overly descriptive
	if len(name) >= 25 || strings.Count(name, "-")+strings.Count(name, "_") >= 3 {
		signals++
	}

	// Signal 3 & 5: Package has no repository
	hasRepo := false
	if repository != nil {
		switch v := repository.(type) {
		case string:
			if v != "" {
				hasRepo = true
			}
		case map[string]any:
			if url, ok := v["url"].(string); ok && url != "" {
				hasRepo = true
			}
		}
	}
	if !hasRepo {
		signals++
	}

	// Signal 6: Package has no meaningful description
	if len(strings.TrimSpace(description)) < 15 {
		signals++
	}

	// Signal 4: Package was published recently (ageDays is 0-14, or -1 if unknown)
	if ageDays >= 0 && ageDays <= 14 {
		signals++
	}

	// Signal 8: Package has install lifecycle scripts
	if hasScripts {
		signals++
	}

	// Heuristic rules for classification:
	// 1. Matches framework squatting pattern and has at least 2 other signals.
	if isSquattingPattern && signals >= 2 {
		return true
	}
	// 2. Ends with a generic suffix, and has at least 3 other signals.
	if hasSuffix && signals >= 3 {
		return true
	}

	return false
}
