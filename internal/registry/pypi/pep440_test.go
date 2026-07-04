package pypi

import "testing"

func TestParsePEP440(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		pre   bool // isPrerelease
		local string
	}{
		{"1.0.0", true, false, ""},
		{"1.0", true, false, ""},
		{"v1.0", true, false, ""},
		{"2024.6", true, false, ""},
		{"1!2.0", true, false, ""},
		{"1.0a1", true, true, ""},
		{"1.0.alpha.2", true, true, ""},
		{"1.0b2", true, true, ""},
		{"1.0rc1", true, true, ""},
		{"1.0.preview1", true, true, ""},
		{"1.0c3", true, true, ""},
		{"1.0.dev3", true, true, ""},
		{"1.0.post1", true, false, ""},
		{"1.0-1", true, false, ""},
		{"1.0.rev2", true, false, ""},
		{"1.0+ubuntu.1", true, false, "ubuntu.1"},
		{"1.0.post1.dev2", true, true, ""},
		{"not-a-version", false, false, ""},
		{"1.0.x", false, false, ""},
		{"", false, false, ""},
	}
	for _, c := range cases {
		v, ok := parsePEP440(c.in)
		if ok != c.ok {
			t.Errorf("parsePEP440(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if v.isPrerelease() != c.pre {
			t.Errorf("parsePEP440(%q) isPrerelease = %v, want %v", c.in, v.isPrerelease(), c.pre)
		}
		if v.local != c.local {
			t.Errorf("parsePEP440(%q) local = %q, want %q", c.in, v.local, c.local)
		}
	}
}

func TestComparePEP440Ordering(t *testing.T) {
	// Strictly ascending per PEP 440; every adjacent pair must compare <.
	ascending := []string{
		"0.9",
		"1.0.dev1",
		"1.0.dev2",
		"1.0a1.dev1",
		"1.0a1",
		"1.0a2",
		"1.0b1",
		"1.0rc1",
		"1.0",
		"1.0+local",
		"1.0.post1.dev1",
		"1.0.post1",
		"1.0.post2",
		"1.0.1",
		"1.1",
		"1.10",
		"2.0",
		"1!0.5",
	}
	for i := 0; i+1 < len(ascending); i++ {
		a, okA := parsePEP440(ascending[i])
		b, okB := parsePEP440(ascending[i+1])
		if !okA || !okB {
			t.Fatalf("failed to parse %q or %q", ascending[i], ascending[i+1])
		}
		if comparePEP440(a, b) >= 0 {
			t.Errorf("expected %q < %q", ascending[i], ascending[i+1])
		}
		if comparePEP440(b, a) <= 0 {
			t.Errorf("expected %q > %q", ascending[i+1], ascending[i])
		}
	}
}

func TestComparePEP440Equivalence(t *testing.T) {
	pairs := [][2]string{
		{"1.0", "1.0.0"},   // trailing zeros insignificant
		{"1.0rc1", "1.0c1"}, // c normalizes to rc
		{"1.0.post1", "1.0-1"},
		{"1.0a1", "1.0.alpha1"},
		{"1.0", "v1.0"},
	}
	for _, p := range pairs {
		a, okA := parsePEP440(p[0])
		b, okB := parsePEP440(p[1])
		if !okA || !okB {
			t.Fatalf("failed to parse %q or %q", p[0], p[1])
		}
		if comparePEP440(a, b) != 0 {
			t.Errorf("expected %q == %q", p[0], p[1])
		}
	}
}

// TestResolveVersionSkipsPrereleases reproduces the httpx gate: a dev release
// that sorts above the latest stable by string/semver comparison must not win
// default resolution.
func TestResolveVersionSkipsPrereleases(t *testing.T) {
	md := Metadata{
		Info: Info{Name: "httpx-like"},
		Releases: map[string][]File{
			"0.28.1":   {{Filename: "p-0.28.1.tar.gz", PackageType: "sdist"}},
			"0.27.0":   {{Filename: "p-0.27.0.tar.gz", PackageType: "sdist"}},
			"1.0.dev3": {{Filename: "p-1.0.dev3.tar.gz", PackageType: "sdist"}},
			"1.0rc1":   {{Filename: "p-1.0rc1.tar.gz", PackageType: "sdist"}},
		},
	}
	vm, err := ResolveVersion(md, "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Version != "0.28.1" {
		t.Fatalf("expected pip-parity stable 0.28.1, got %s", vm.Version)
	}
}

func TestResolveVersionPrereleaseOnlyPackage(t *testing.T) {
	md := Metadata{
		Info: Info{Name: "pre-only"},
		Releases: map[string][]File{
			"1.0a1": {{Filename: "p-1.0a1.tar.gz", PackageType: "sdist"}},
			"1.0b2": {{Filename: "p-1.0b2.tar.gz", PackageType: "sdist"}},
		},
	}
	vm, err := ResolveVersion(md, "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Version != "1.0b2" {
		t.Fatalf("expected highest pre-release 1.0b2 when no stable exists, got %s", vm.Version)
	}
}

func TestResolveVersionExplicitPrereleasePin(t *testing.T) {
	md := Metadata{
		Info: Info{Name: "pinned"},
		Releases: map[string][]File{
			"2.0":      {{Filename: "p-2.0.tar.gz", PackageType: "sdist"}},
			"3.0.dev1": {{Filename: "p-3.0.dev1.tar.gz", PackageType: "sdist"}},
		},
	}
	vm, err := ResolveVersion(md, "3.0.dev1")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Version != "3.0.dev1" {
		t.Fatalf("explicit pre-release pin must resolve exactly, got %s", vm.Version)
	}
}

func TestResolveVersionCalendarVersions(t *testing.T) {
	// CalVer releases (pytz-style) exceed semver's field width assumptions.
	md := Metadata{
		Info: Info{Name: "calver"},
		Releases: map[string][]File{
			"2024.1":  {{Filename: "p-2024.1.tar.gz", PackageType: "sdist"}},
			"2024.10": {{Filename: "p-2024.10.tar.gz", PackageType: "sdist"}},
			"2024.2":  {{Filename: "p-2024.2.tar.gz", PackageType: "sdist"}},
		},
	}
	vm, err := ResolveVersion(md, "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Version != "2024.10" {
		t.Fatalf("expected numeric ordering 2024.10 > 2024.2, got %s", vm.Version)
	}
}
