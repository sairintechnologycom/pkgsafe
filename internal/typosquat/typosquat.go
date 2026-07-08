package typosquat

import (
	"context"
	"strings"
	"sync"

	"github.com/sairintechnologycom/pkgsafe/internal/db"
)

var PopularNPM = []string{
	"react", "vue", "angular", "axios", "lodash", "express", "next", "vite", "webpack", "typescript",
	"eslint", "prettier", "jest", "mocha", "chalk", "commander", "yargs", "moment", "dayjs", "uuid",
	"mongoose", "sequelize", "nestjs", "redux", "rxjs", "tailwindcss", "socket.io", "dotenv", "debug", "glob",
}

func Check(name string) []string {
	return CheckEcosystem("npm", name)
}

var PopularPyPI = []string{
	"requests", "flask", "django", "fastapi", "numpy", "pandas", "scipy", "scikit-learn",
	"tensorflow", "torch", "transformers", "langchain", "openai", "anthropic", "pydantic",
	"sqlalchemy", "pytest", "beautifulsoup4", "boto3", "azure-identity", "google-cloud-storage",
}

var (
	loadedPopularOnce sync.Once
	popularNPMCache   []string
	popularPyPICache  []string
)

func lazyLoadPopularFromDB() {
	loadedPopularOnce.Do(func() {
		// Open the default database path
		d, err := db.Open("")
		if err != nil {
			return
		}
		defer d.Close()

		ctx := context.Background()
		npmPkgs, err := d.GetPopularPackages(ctx, "npm")
		if err == nil && len(npmPkgs) > 0 {
			var names []string
			for _, p := range npmPkgs {
				names = append(names, p.Name)
			}
			popularNPMCache = names
		}

		pypiPkgs, err := d.GetPopularPackages(ctx, "pypi")
		if err == nil && len(pypiPkgs) > 0 {
			var names []string
			for _, p := range pypiPkgs {
				names = append(names, p.Name)
			}
			popularPyPICache = names
		}
	})
}

func CheckEcosystem(ecosystem, name string) []string {
	lazyLoadPopularFromDB()

	clean := normalize(name)
	var alts []string
	baseline := PopularNPM
	if len(popularNPMCache) > 0 {
		baseline = popularNPMCache
	}
	if strings.EqualFold(ecosystem, "pypi") {
		baseline = PopularPyPI
		if len(popularPyPICache) > 0 {
			baseline = popularPyPICache
		}
	}
	for _, p := range baseline {
		pp := normalize(p)
		if clean == pp {
			continue
		}
		d := levenshtein(clean, pp)
		if d > 0 && d <= 2 {
			alts = append(alts, p)
			continue
		}
		if strings.Contains(clean, pp) && clean != pp && len(clean)-len(pp) <= 6 {
			alts = append(alts, p)
		}
	}
	return unique(alts)
}

func normalize(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "@")
	s = strings.ReplaceAll(s, "/", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, ".", "")
	return s
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
		dp[i][0] = i
	}
	for j := range dp[0] {
		dp[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
		}
	}
	return dp[len(a)][len(b)]
}

func min(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ResetCacheForTest clears the dynamic cache and sync.Once state for testing.
func ResetCacheForTest(npm, pypi []string) {
	popularNPMCache = npm
	popularPyPICache = pypi
	loadedPopularOnce = sync.Once{}
}

