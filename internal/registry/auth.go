package registry

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/niyam-ai/pkgsafe/internal/policy"
)

func AddAuthHeader(req *http.Request, cfg policy.RegistryConfig) error {
	switch cfg.Auth.Method {
	case "env_token":
		if cfg.Auth.TokenEnv == "" {
			return fmt.Errorf("missing token_env configuration")
		}
		token := os.Getenv(cfg.Auth.TokenEnv)
		if token == "" {
			return fmt.Errorf("Missing required environment variable %s", cfg.Auth.TokenEnv)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case "basic_env":
		if cfg.Auth.UsernameEnv == "" || cfg.Auth.PasswordEnv == "" {
			return fmt.Errorf("missing basic auth environment variables configuration")
		}
		username := os.Getenv(cfg.Auth.UsernameEnv)
		password := os.Getenv(cfg.Auth.PasswordEnv)
		if username == "" || password == "" {
			return fmt.Errorf("Missing required basic auth environment variables: %s, %s", cfg.Auth.UsernameEnv, cfg.Auth.PasswordEnv)
		}
		req.SetBasicAuth(username, password)
	case "npmrc":
		token, err := findTokenInNpmrc(cfg.URL)
		if err != nil {
			return err
		}
		if token == "" {
			// fallback to environment token NPM_TOKEN if set
			token = os.Getenv(cfg.Auth.TokenEnv)
			if token == "" {
				token = os.Getenv("NPM_TOKEN")
			}
			if token == "" {
				return fmt.Errorf("could not find token in .npmrc or NPM_TOKEN environment variable")
			}
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

func findTokenInNpmrc(registryURL string) (string, error) {
	// Parse registry URL host and path
	u, err := url.Parse(registryURL)
	if err != nil {
		return "", nil
	}
	regKey := u.Host + u.Path
	regKey = strings.Trim(regKey, "/")

	home, _ := os.UserHomeDir()
	npmrcPaths := []string{
		filepath.Join(".", ".npmrc"),
	}
	if home != "" {
		npmrcPaths = append(npmrcPaths, filepath.Join(home, ".npmrc"))
	}

	for _, path := range npmrcPaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
				continue
			}

			// Format matches: //registry.npmjs.org/:_authToken=...
			if strings.Contains(line, ":_authToken=") {
				parts := strings.SplitN(line, ":_authToken=", 2)
				key := strings.TrimPrefix(parts[0], ":")
				key = strings.Trim(key, "/")
				if strings.Contains(regKey, key) || strings.Contains(key, regKey) {
					token := strings.TrimSpace(parts[1])
					// Expand env vars in token like ${NPM_TOKEN}
					re := regexp.MustCompile(`\$\{(.+?)\}`)
					token = re.ReplaceAllStringFunc(token, func(match string) string {
						envVar := re.FindStringSubmatch(match)[1]
						return os.Getenv(envVar)
					})
					return token, nil
				}
			}
		}
	}
	return "", nil
}
