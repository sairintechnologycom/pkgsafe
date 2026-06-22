package typosquat

import "testing"

func TestCheckEcosystemPyPI(t *testing.T) {
	alts := CheckEcosystem("pypi", "reqeusts")
	if len(alts) == 0 || alts[0] != "requests" {
		t.Fatalf("expected requests typosquat candidate, got %+v", alts)
	}
}
