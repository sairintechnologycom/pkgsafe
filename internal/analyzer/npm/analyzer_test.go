package npm

import (
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
