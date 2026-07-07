// Package license provides offline, fail-open verification of PkgSafe
// enterprise entitlement tokens.
//
// This package is verification-only: it holds no signing key and cannot mint
// licenses. The signing key and issuance tooling live in the private
// licensing service. Shipping only the verifier here is safe to open source
// and lets downstream distributions (the private pkgsafe-enterprise binary)
// resolve entitlement without duplicating the token format.
//
// # Fail-open contract
//
// PkgSafe is a security tool. An absent, expired, tampered, or otherwise
// unresolvable license must NEVER halt the program or disable scanning — it
// must only withhold premium features. That contract is encoded in the types:
// Resolve always returns a non-nil *Entitlement and never returns an error,
// and (*Entitlement).Allows is nil-safe and returns false for every non-active
// state. A caller therefore cannot accidentally fail closed.
//
// The public OSS pkgsafe binary configures no keys and so always resolves to
// StatusAbsent (i.e. OSS behavior). The private enterprise binary injects its
// production public key(s) and gates features on Allows.
package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SchemaVersion is the token payload schema this build understands. Tokens
// carrying a newer major schema are treated as invalid (fail-open) rather than
// parsed on a best-effort basis.
const SchemaVersion = 1

// Status is the resolved state of a license at evaluation time.
type Status string

const (
	// StatusActive means the license verified and is within its validity
	// window. Premium features are granted.
	StatusActive Status = "active"
	// StatusGrace means the license verified but is past not_after yet still
	// within the grace window. Premium features are granted, but the caller
	// should warn loudly on every invocation.
	StatusGrace Status = "grace"
	// StatusExpired means the license verified but is past not_after + grace.
	// Premium features are withheld; scanning is unaffected.
	StatusExpired Status = "expired"
	// StatusInvalid means a license was present but failed signature, schema,
	// or structural validation (tampered, wrong key, unknown kid, corrupt).
	// Premium features are withheld; scanning is unaffected.
	StatusInvalid Status = "invalid"
	// StatusAbsent means no license was found, or no verifying keys were
	// configured (the OSS default). Premium features are withheld silently.
	StatusAbsent Status = "absent"
)

// Feature keys gate individual enterprise capabilities. Kept as constants so
// call sites and tokens agree on the exact spelling.
const (
	FeatureSignedBundles  = "signed-bundles"
	FeatureSignedPolicy   = "signed-policy"
	FeatureSignedEvidence = "signed-evidence"
	FeatureReportDiff     = "report-diff"
	FeatureRemoteDist     = "remotedist"
	FeatureWarnBroker     = "warn-broker"
)

// Claim is the signed license payload. Field names are the on-the-wire JSON
// keys; keep them stable across releases (bump SchemaVersion for breaking
// changes).
type Claim struct {
	V         int       `json:"v"`
	LicenseID string    `json:"license_id"`
	Org       string    `json:"org"`
	Tier      string    `json:"tier"`
	Seats     int       `json:"seats"`
	Features  []string  `json:"features"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`
	GraceDays int       `json:"grace_days"`
	Issuer    string    `json:"issuer"`
}

// envelope is the file/env wire format: a detached ed25519 signature over the
// exact payload bytes. Signing over the stored bytes (rather than a
// re-canonicalized claim) removes any JSON-canonicalization ambiguity.
type envelope struct {
	// KID identifies which public key signed the token, enabling key
	// rotation: verifiers hold several keys and select by kid.
	KID string `json:"kid"`
	// Payload is base64url(claim JSON).
	Payload string `json:"payload"`
	// Sig is base64url(ed25519 signature over the decoded payload bytes).
	Sig string `json:"sig"`
}

// Entitlement is the resolved, fail-open-safe capability set. The zero value
// and any nil *Entitlement grant nothing (OSS behavior). Construct only via
// Resolve.
type Entitlement struct {
	Status    Status
	Tier      string
	Org       string
	Seats     int
	LicenseID string
	NotAfter  time.Time
	// Source records where the token was loaded from, for diagnostics.
	Source string
	// Reason is a short machine-facing note on why the status was assigned
	// (e.g. "signature mismatch", "unknown kid"). Empty for clean states.
	Reason string

	features map[string]bool
}

// Allows reports whether feature is granted. It is nil-safe: a nil receiver
// (OSS, or any unresolved path) and every non-active/grace status return
// false. This is the single fail-open chokepoint every gate should call.
func (e *Entitlement) Allows(feature string) bool {
	if e == nil {
		return false
	}
	if e.Status != StatusActive && e.Status != StatusGrace {
		return false
	}
	return e.features[feature]
}

// Active reports whether premium features are currently granted (active or in
// grace). Convenience for callers that gate a whole mode rather than a
// feature.
func (e *Entitlement) Active() bool {
	return e != nil && (e.Status == StatusActive || e.Status == StatusGrace)
}

// Message returns a one-line, user-facing summary suitable for stderr. It
// always reassures that scanning is unaffected when premium is withheld, per
// the fail-open contract.
func (e *Entitlement) Message() string {
	if e == nil {
		return ""
	}
	switch e.Status {
	case StatusActive:
		return ""
	case StatusGrace:
		return "pkgsafe: license expired " + e.NotAfter.Format("2006-01-02") +
			"; within grace period — renew soon to avoid losing enterprise features"
	case StatusExpired:
		return "pkgsafe: license expired; enterprise features disabled, scanning unaffected — renew to re-enable"
	case StatusInvalid:
		return "pkgsafe: license could not be verified (" + e.Reason +
			"); enterprise features disabled, scanning unaffected"
	default: // StatusAbsent
		return ""
	}
}

// Resolver loads and verifies a license. It is fail-open by construction:
// Resolve never returns an error and never panics on malformed input.
//
// The zero Resolver (no keys) always resolves to StatusAbsent, which is the
// correct OSS default. The enterprise binary populates Keys with its embedded
// production public key(s).
type Resolver struct {
	// Keys maps a kid to its ed25519 public key. Multiple entries support key
	// rotation. An empty map disables verification (StatusAbsent).
	Keys map[string]ed25519.PublicKey

	// ExplicitPath, when set (e.g. from a --license flag), is tried first.
	ExplicitPath string

	// EnvVar is the environment variable holding a base64 (or raw JSON)
	// token. Defaults to "PKGSAFE_LICENSE" when empty.
	EnvVar string

	// ConfigPaths are ordered file locations tried after the flag and env.
	// When nil, DefaultConfigPaths(getenv) is used.
	ConfigPaths []string

	// Now is an injectable clock for hermetic tests. Nil means time.Now.
	Now func() time.Time

	// Getenv is an injectable environment accessor for hermetic tests. Nil
	// means os.Getenv.
	Getenv func(string) string
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) getenv(k string) string {
	if r.Getenv != nil {
		return r.Getenv(k)
	}
	return os.Getenv(k)
}

// DefaultConfigPaths returns the standard ordered license file locations,
// resolved against the provided environment accessor (pass os.Getenv in
// production; a stub in tests). Highest priority first.
func DefaultConfigPaths(getenv func(string) string) []string {
	if getenv == nil {
		getenv = os.Getenv
	}
	var paths []string
	if xdg := getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "pkgsafe", "license"))
	} else if home := getenv("HOME"); home != "" {
		paths = append(paths, filepath.Join(home, ".config", "pkgsafe", "license"))
	}
	paths = append(paths, filepath.Join("/etc", "pkgsafe", "license"))
	return paths
}

// Resolve loads a token from the configured sources and returns the resolved
// entitlement. It always returns a non-nil *Entitlement and never an error:
// any failure maps to StatusAbsent (nothing found) or StatusInvalid
// (found but unverifiable), so callers cannot fail closed.
func (r *Resolver) Resolve() *Entitlement {
	// No verifying keys configured → this is the OSS build. Nothing to do.
	if len(r.Keys) == 0 {
		return &Entitlement{Status: StatusAbsent, Reason: "no verifying keys configured"}
	}

	raw, source := r.loadRaw()
	if raw == nil {
		return &Entitlement{Status: StatusAbsent}
	}

	env, err := decodeEnvelope(raw)
	if err != nil {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "malformed envelope"}
	}

	pub, ok := r.Keys[env.KID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "unknown signing key"}
	}

	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "malformed payload"}
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Sig)
	if err != nil {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "malformed signature"}
	}
	if !ed25519.Verify(pub, payload, sig) {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "signature mismatch"}
	}

	var claim Claim
	if err := json.Unmarshal(payload, &claim); err != nil {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "malformed claim"}
	}
	if claim.V != SchemaVersion {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "unsupported schema version"}
	}
	if claim.NotAfter.IsZero() {
		return &Entitlement{Status: StatusInvalid, Source: source, Reason: "missing expiry"}
	}

	ent := &Entitlement{
		Tier:      claim.Tier,
		Org:       claim.Org,
		Seats:     claim.Seats,
		LicenseID: claim.LicenseID,
		NotAfter:  claim.NotAfter,
		Source:    source,
		features:  featureSet(claim.Features),
	}
	ent.Status = evaluateStatus(r.now(), claim.NotAfter, claim.GraceDays)
	return ent
}

// evaluateStatus derives the time-based status. graceDays is clamped to a
// non-negative value.
func evaluateStatus(now, notAfter time.Time, graceDays int) Status {
	if now.Before(notAfter) {
		return StatusActive
	}
	if graceDays < 0 {
		graceDays = 0
	}
	graceEnd := notAfter.AddDate(0, 0, graceDays)
	if now.Before(graceEnd) {
		return StatusGrace
	}
	return StatusExpired
}

func featureSet(features []string) map[string]bool {
	m := make(map[string]bool, len(features))
	for _, f := range features {
		f = strings.TrimSpace(f)
		if f != "" {
			m[f] = true
		}
	}
	return m
}

// loadRaw returns the first token bytes found across the configured sources,
// with a human-readable source label. Returns nil when nothing is found.
func (r *Resolver) loadRaw() ([]byte, string) {
	if r.ExplicitPath != "" {
		if b, err := os.ReadFile(r.ExplicitPath); err == nil && len(bytes.TrimSpace(b)) > 0 {
			return b, r.ExplicitPath
		}
	}

	envVar := r.EnvVar
	if envVar == "" {
		envVar = "PKGSAFE_LICENSE"
	}
	if v := strings.TrimSpace(r.getenv(envVar)); v != "" {
		return []byte(v), "$" + envVar
	}

	paths := r.ConfigPaths
	if paths == nil {
		paths = DefaultConfigPaths(r.Getenv)
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(b)) > 0 {
			return b, p
		}
	}
	return nil, ""
}

// decodeEnvelope parses the wire format tolerantly: raw JSON is used directly;
// otherwise the bytes are treated as base64 (any common variant) of the JSON.
// This lets a file hold plain JSON while an env var holds base64 of the same.
func decodeEnvelope(raw []byte) (envelope, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var e envelope
		err := json.Unmarshal(trimmed, &e)
		return e, err
	}
	decoded := decodeBase64Any(string(trimmed))
	if decoded == nil {
		return envelope{}, errMalformed
	}
	var e envelope
	err := json.Unmarshal(decoded, &e)
	return e, err
}

// decodeBase64Any tries the common base64 alphabets/paddings and returns the
// first successful decode, or nil.
func decodeBase64Any(s string) []byte {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b
		}
	}
	return nil
}

// errMalformed is returned when bytes are neither JSON nor valid base64.
var errMalformed = &malformedError{}

type malformedError struct{}

func (*malformedError) Error() string { return "license: malformed token bytes" }
