package registry_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/registry"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://user:pass@npm.company.com/", "https://REDACTED:REDACTED@npm.company.com/"},
		{"https://npm.company.com/", "https://npm.company.com/"},
		{"http://company.com/pypi", "http://company.com/pypi"},
	}

	for _, tc := range tests {
		got := registry.RedactURL(tc.input)
		if got != tc.expected {
			t.Errorf("RedactURL(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	input := "Authorization: Bearer mysecrettoken123\nAuthorization: Basic dXNlcjpwYXNz"
	expected := "Authorization: Bearer REDACTED\nAuthorization: Basic REDACTED"

	got := registry.RedactSecrets(input)
	if got != expected {
		t.Errorf("RedactSecrets output mismatch:\ngot:\n%s\nexpected:\n%s", got, expected)
	}
}

func TestAddAuthHeaderEnvToken(t *testing.T) {
	os.Setenv("TEST_NPM_TOKEN", "supersecrettoken")
	defer os.Unsetenv("TEST_NPM_TOKEN")

	cfg := policy.RegistryConfig{
		Auth: policy.RegistryAuth{
			Method:   "env_token",
			TokenEnv: "TEST_NPM_TOKEN",
		},
	}

	req, _ := http.NewRequest("GET", "https://npm.company.com", nil)
	err := registry.AddAuthHeader(req, cfg)
	if err != nil {
		t.Fatal(err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer supersecrettoken" {
		t.Errorf("unexpected authorization header: %q", authHeader)
	}
}

func TestAddAuthHeaderEnvTokenMissing(t *testing.T) {
	cfg := policy.RegistryConfig{
		Auth: policy.RegistryAuth{
			Method:   "env_token",
			TokenEnv: "NON_EXISTENT_TOKEN_VAR",
		},
	}

	req, _ := http.NewRequest("GET", "https://npm.company.com", nil)
	err := registry.AddAuthHeader(req, cfg)
	if err == nil {
		t.Fatalf("expected error due to missing token environment variable")
	}
}

func TestAddAuthHeaderBasicEnv(t *testing.T) {
	os.Setenv("TEST_USER", "admin")
	os.Setenv("TEST_PASS", "secretpassword")
	defer func() {
		os.Unsetenv("TEST_USER")
		os.Unsetenv("TEST_PASS")
	}()

	cfg := policy.RegistryConfig{
		Auth: policy.RegistryAuth{
			Method:      "basic_env",
			UsernameEnv: "TEST_USER",
			PasswordEnv: "TEST_PASS",
		},
	}

	req, _ := http.NewRequest("GET", "https://npm.company.com", nil)
	err := registry.AddAuthHeader(req, cfg)
	if err != nil {
		t.Fatal(err)
	}

	username, password, ok := req.BasicAuth()
	if !ok || username != "admin" || password != "secretpassword" {
		t.Errorf("basic auth headers not set correctly: username=%q, ok=%v", username, ok)
	}
}

func TestAddAuthHeaderNpmrc(t *testing.T) {
	tempDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempDir)
	defer os.Setenv("HOME", origHome)

	// Write mock .npmrc
	npmrcContent := "//npm.company.com/:_authToken=npmrcsecret\n"
	err := os.WriteFile(filepath.Join(tempDir, ".npmrc"), []byte(npmrcContent), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := policy.RegistryConfig{
		URL: "https://npm.company.com/",
		Auth: policy.RegistryAuth{
			Method: "npmrc",
		},
	}

	req, _ := http.NewRequest("GET", "https://npm.company.com/", nil)
	err = registry.AddAuthHeader(req, cfg)
	if err != nil {
		t.Fatal(err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer npmrcsecret" {
		t.Errorf("expected token from npmrc, got: %q", authHeader)
	}
}

func TestTestRegistry(t *testing.T) {
	// Setup test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond OK
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"test-reg": {
				URL:     server.URL,
				Type:    "private",
				Enabled: true,
			},
		},
	}

	res, err := registry.TestRegistry("test-reg", pol)
	if err != nil {
		t.Fatal(err)
	}

	if res.Status != "OK" {
		t.Errorf("expected OK status, got %s (Reason: %s)", res.Status, res.Reason)
	}
}

func TestTestRegistryFailure(t *testing.T) {
	pol := policy.Default()
	pol.Registries.Registries = map[string]map[string]policy.RegistryConfig{
		"npm": {
			"nonexistent": {
				URL:     "http://127.0.0.1:9999/invalid",
				Type:    "private",
				Enabled: true,
			},
		},
	}

	res, err := registry.TestRegistry("nonexistent", pol)
	if err != nil {
		t.Fatal(err)
	}

	if res.Status != "FAILED" {
		t.Errorf("expected status FAILED, got %s", res.Status)
	}
}
