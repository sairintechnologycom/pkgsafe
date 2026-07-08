package pypi

import (
	"regexp"
	"strconv"
	"strings"
)

// pep440Version is a parsed PEP 440 version. Ordering follows the canonical
// sort key used by pip's packaging library: within one release number,
// .devN < aN < bN < rcN < final < .postN.
type pep440Version struct {
	epoch   int
	release []int
	preL    int // 0=a, 1=b, 2=rc; meaningful only when hasPre
	preN    int
	hasPre  bool
	postN   int
	hasPost bool
	devN    int
	hasDev  bool
	local   string
}

// pep440Pattern is the normalization-tolerant grammar from PEP 440 Appendix B:
// optional epoch, dotted release, and optional pre/post/dev/local segments with
// interchangeable [-_.] separators and spelling aliases (alpha, beta, c, rev,
// bare "-N" for post).
var pep440Pattern = regexp.MustCompile(`^v?` +
	`(?:([0-9]+)!)?` + // 1: epoch
	`([0-9]+(?:\.[0-9]+)*)` + // 2: release
	`(?:[-_.]?(alpha|beta|preview|pre|a|b|c|rc)[-_.]?([0-9]+)?)?` + // 3: pre letter, 4: pre number
	`(?:-([0-9]+)|([-_.]?(?:post|rev|r))[-_.]?([0-9]+)?)?` + // 5: bare post, 6: spelled post marker, 7: its number
	`(?:([-_.]?dev)[-_.]?([0-9]+)?)?` + // 8: dev marker, 9: dev number
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`) // 10: local

func parsePEP440(s string) (pep440Version, bool) {
	m := pep440Pattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440Version{}, false
	}
	var v pep440Version
	v.epoch = atoiDefault(m[1], 0)
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return pep440Version{}, false
		}
		v.release = append(v.release, n)
	}
	if m[3] != "" {
		v.hasPre = true
		switch m[3] {
		case "a", "alpha":
			v.preL = 0
		case "b", "beta":
			v.preL = 1
		default: // c, rc, pre, preview all normalize to rc
			v.preL = 2
		}
		v.preN = atoiDefault(m[4], 0)
	}
	if m[5] != "" {
		v.hasPost, v.postN = true, atoiDefault(m[5], 0)
	} else if m[6] != "" {
		v.hasPost, v.postN = true, atoiDefault(m[7], 0)
	}
	if m[8] != "" {
		v.hasDev, v.devN = true, atoiDefault(m[9], 0)
	}
	v.local = m[10]
	return v, true
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// isPrerelease reports whether pip's default resolution would skip this
// version: any dev or pre segment marks it, post/local do not.
func (v pep440Version) isPrerelease() bool {
	return v.hasPre || v.hasDev
}

// comparePEP440 returns -1, 0, or 1 mirroring packaging's _cmpkey ordering.
func comparePEP440(a, b pep440Version) int {
	if a.epoch != b.epoch {
		return cmpInt(a.epoch, b.epoch)
	}
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	// Pre segment: a bare .devN (no pre, no post) sorts before any pre-release
	// of the same version; a final release sorts after all of them.
	if c := cmpInt(preRank(a), preRank(b)); c != 0 {
		return c
	}
	if a.hasPre && b.hasPre {
		if c := cmpInt(a.preL, b.preL); c != 0 {
			return c
		}
		if c := cmpInt(a.preN, b.preN); c != 0 {
			return c
		}
	}
	// Post segment: absent sorts before present.
	if c := cmpOptionalInt(a.hasPost, a.postN, b.hasPost, b.postN, false); c != 0 {
		return c
	}
	// Dev segment: absent sorts after present (1.0.post1.dev1 < 1.0.post1).
	if c := cmpOptionalInt(a.hasDev, a.devN, b.hasDev, b.devN, true); c != 0 {
		return c
	}
	return strings.Compare(a.local, b.local)
}

// preRank buckets the pre-segment state for ordering: bare dev releases
// lowest, then pre-releases, then everything final.
func preRank(v pep440Version) int {
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		return 0
	case v.hasPre:
		return 1
	default:
		return 2
	}
}

func cmpRelease(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return cmpInt(av, bv)
		}
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// cmpOptionalInt orders an optional numeric segment. absentHigh selects
// whether a missing segment sorts above (dev) or below (post) a present one.
func cmpOptionalInt(aHas bool, aN int, bHas bool, bN int, absentHigh bool) int {
	if aHas != bHas {
		if aHas != absentHigh {
			return 1
		}
		return -1
	}
	if aHas {
		return cmpInt(aN, bN)
	}
	return 0
}

// ComparePEP440Strings compares two PEP 440 version strings.
// Returns -1 if a < b, 0 if a == b, and 1 if a > b.
// If either version cannot be parsed under PEP 440, it falls back to standard string comparison.
func ComparePEP440Strings(a, b string) int {
	vA, okA := parsePEP440(a)
	vB, okB := parsePEP440(b)
	if !okA || !okB {
		return strings.Compare(a, b)
	}
	return comparePEP440(vA, vB)
}

