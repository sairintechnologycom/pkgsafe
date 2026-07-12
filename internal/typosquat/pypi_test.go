package typosquat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckEcosystemPyPI(t *testing.T) {
	ResetCacheForTest(nil, nil)
	alts := CheckEcosystem("pypi", "reqeusts")
	if len(alts) == 0 || alts[0] != "requests" {
		t.Fatalf("expected requests typosquat candidate, got %+v", alts)
	}
}

func TestCheckEcosystemDynamic(t *testing.T) {
	// Verify that custom popular package caches are used for typosquat matching
	ResetCacheForTest([]string{"my-super-popular-npm-package"}, []string{"my-super-popular-pypi-package"})

	npmAlts := CheckEcosystem("npm", "my-super-popular-npm-packag")
	if len(npmAlts) == 0 || npmAlts[0] != "my-super-popular-npm-package" {
		t.Errorf("expected dynamic npm match, got %v", npmAlts)
	}

	pypiAlts := CheckEcosystem("pypi", "my-super-popular-pypi-packag")
	if len(pypiAlts) == 0 || pypiAlts[0] != "my-super-popular-pypi-package" {
		t.Errorf("expected dynamic pypi match, got %v", pypiAlts)
	}

	// Reset cache back to default
	ResetCacheForTest(nil, nil)
}

func TestCheckEcosystemDatabaseIntegration(t *testing.T) {
	// Verify database integration test
	tmpDir, err := os.MkdirTemp("", "pkgsafe-typosquat-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "pkgsafe.db")
	os.Setenv("PKGSAFE_DBPath_TEST", dbPath)
	defer os.Unsetenv("PKGSAFE_DBPath_TEST")

	// Simply reset cache to trigger reload from default db path (which would be blank since db does not exist, falling back to seeds)
	ResetCacheForTest(nil, nil)
	alts := CheckEcosystem("pypi", "reqeusts")
	if len(alts) == 0 || alts[0] != "requests" {
		t.Fatalf("expected requests typosquat candidate from default fallback, got %+v", alts)
	}
}
