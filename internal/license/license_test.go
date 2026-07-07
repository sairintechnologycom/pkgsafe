package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testKID is the key id used across fixtures.
const testKID = "test-key-1"

// fixed reference clock: 2026-07-01T00:00:00Z. All fixtures are relative to it.
func refNow() time.Time {
	return time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
}

// signToken mints a signed envelope for tests. Signing lives only in the test
// (the package itself is verification-only).
func signToken(t *testing.T, priv ed25519.PrivateKey, kid string, claim Claim) []byte {
	t.Helper()
	payload, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("marshal claim: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	env := envelope{
		KID:     kid,
		Payload: base64.RawURLEncoding.EncodeToString(payload),
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func validClaim() Claim {
	return Claim{
		V:         SchemaVersion,
		LicenseID: "lic_test",
		Org:       "acme",
		Tier:      "enterprise",
		Seats:     25,
		Features:  []string{FeatureSignedBundles, FeatureWarnBroker, FeatureReportDiff},
		IssuedAt:  refNow().AddDate(0, 0, -30),
		NotAfter:  refNow().AddDate(0, 0, 30), // expires 30 days after refNow
		GraceDays: 14,
		Issuer:    "pkgsafe-licensing-v1",
	}
}

// resolverFor builds a Resolver with the given token bytes delivered via env,
// a fixed clock, and the given key registered.
func resolverFor(pub ed25519.PublicKey, token []byte, now time.Time) *Resolver {
	env := map[string]string{"PKGSAFE_LICENSE": string(token)}
	return &Resolver{
		Keys:   map[string]ed25519.PublicKey{testKID: pub},
		Now:    func() time.Time { return now },
		Getenv: func(k string) string { return env[k] },
	}
}

func TestResolve_ActiveGrantsFeatures(t *testing.T) {
	pub, priv := newKeypair(t)
	token := signToken(t, priv, testKID, validClaim())
	ent := resolverFor(pub, token, refNow()).Resolve()

	if ent.Status != StatusActive {
		t.Fatalf("status = %q, want active", ent.Status)
	}
	if !ent.Allows(FeatureSignedBundles) {
		t.Error("expected signed-bundles allowed")
	}
	if !ent.Allows(FeatureWarnBroker) {
		t.Error("expected warn-broker allowed")
	}
	if ent.Allows(FeatureRemoteDist) {
		t.Error("remotedist not in token; must not be allowed")
	}
	if !ent.Active() {
		t.Error("expected Active() true")
	}
	if ent.Message() != "" {
		t.Errorf("active license should have empty message, got %q", ent.Message())
	}
}

func TestResolve_GraceStillGrantsButWarns(t *testing.T) {
	pub, priv := newKeypair(t)
	token := signToken(t, priv, testKID, validClaim())
	// 5 days past not_after (grace is 14 days) → grace.
	now := validClaim().NotAfter.AddDate(0, 0, 5)
	ent := resolverFor(pub, token, now).Resolve()

	if ent.Status != StatusGrace {
		t.Fatalf("status = %q, want grace", ent.Status)
	}
	if !ent.Allows(FeatureSignedBundles) {
		t.Error("grace period must still grant features")
	}
	if ent.Message() == "" {
		t.Error("grace period must produce a loud warning message")
	}
}

func TestResolve_ExpiredWithholdsButFailsOpen(t *testing.T) {
	pub, priv := newKeypair(t)
	token := signToken(t, priv, testKID, validClaim())
	// 20 days past not_after (> 14 grace) → expired.
	now := validClaim().NotAfter.AddDate(0, 0, 20)
	ent := resolverFor(pub, token, now).Resolve()

	if ent.Status != StatusExpired {
		t.Fatalf("status = %q, want expired", ent.Status)
	}
	if ent.Allows(FeatureSignedBundles) {
		t.Error("expired license must not grant features")
	}
	if ent.Active() {
		t.Error("expired must not be Active()")
	}
	if ent.Message() == "" {
		t.Error("expired should surface a renew message")
	}
}

func TestEvaluateStatus_Boundaries(t *testing.T) {
	notAfter := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	grace := 14
	cases := []struct {
		name string
		now  time.Time
		want Status
	}{
		{"just before expiry", notAfter.Add(-time.Second), StatusActive},
		{"exactly at expiry", notAfter, StatusGrace},
		{"one second into grace", notAfter.Add(time.Second), StatusGrace},
		{"just before grace end", notAfter.AddDate(0, 0, grace).Add(-time.Second), StatusGrace},
		{"exactly at grace end", notAfter.AddDate(0, 0, grace), StatusExpired},
		{"well past grace", notAfter.AddDate(0, 0, grace+30), StatusExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evaluateStatus(c.now, notAfter, grace); got != c.want {
				t.Errorf("evaluateStatus(%v) = %q, want %q", c.now, got, c.want)
			}
		})
	}
}

func TestResolve_TamperedPayloadIsInvalid(t *testing.T) {
	pub, priv := newKeypair(t)
	token := signToken(t, priv, testKID, validClaim())

	// Flip the claim after signing: re-encode a different payload but keep the
	// original signature.
	var env envelope
	if err := json.Unmarshal(token, &env); err != nil {
		t.Fatal(err)
	}
	tampered := validClaim()
	tampered.Seats = 9999
	tp, _ := json.Marshal(tampered)
	env.Payload = base64.RawURLEncoding.EncodeToString(tp)
	badToken, _ := json.Marshal(env)

	ent := resolverFor(pub, badToken, refNow()).Resolve()
	if ent.Status != StatusInvalid {
		t.Fatalf("status = %q, want invalid", ent.Status)
	}
	if ent.Allows(FeatureSignedBundles) {
		t.Error("tampered token must not grant features")
	}
}

func TestResolve_WrongKeyIsInvalid(t *testing.T) {
	_, priv := newKeypair(t)     // signer
	otherPub, _ := newKeypair(t) // verifier holds a different key
	token := signToken(t, priv, testKID, validClaim())

	ent := resolverFor(otherPub, token, refNow()).Resolve()
	if ent.Status != StatusInvalid {
		t.Fatalf("status = %q, want invalid (signature mismatch)", ent.Status)
	}
}

func TestResolve_UnknownKIDIsInvalid(t *testing.T) {
	pub, priv := newKeypair(t)
	token := signToken(t, priv, "some-other-kid", validClaim())

	// Verifier only knows testKID.
	ent := resolverFor(pub, token, refNow()).Resolve()
	if ent.Status != StatusInvalid || ent.Reason != "unknown signing key" {
		t.Fatalf("status=%q reason=%q, want invalid/unknown signing key", ent.Status, ent.Reason)
	}
}

func TestResolve_KeyRotationVerifiesEitherKey(t *testing.T) {
	pubOld, privOld := newKeypair(t)
	pubNew, privNew := newKeypair(t)
	resolver := func(token []byte) *Resolver {
		env := map[string]string{"PKGSAFE_LICENSE": string(token)}
		return &Resolver{
			Keys: map[string]ed25519.PublicKey{
				"key-old": pubOld,
				"key-new": pubNew,
			},
			Now:    refNow,
			Getenv: func(k string) string { return env[k] },
		}
	}
	oldTok := signToken(t, privOld, "key-old", validClaim())
	newTok := signToken(t, privNew, "key-new", validClaim())

	if s := resolver(oldTok).Resolve().Status; s != StatusActive {
		t.Errorf("old-key token: status %q, want active", s)
	}
	if s := resolver(newTok).Resolve().Status; s != StatusActive {
		t.Errorf("new-key token: status %q, want active", s)
	}
}

func TestResolve_NoKeysConfiguredIsAbsent_OSSDefault(t *testing.T) {
	// The OSS build: zero Resolver, no keys. Must be absent and grant nothing.
	ent := (&Resolver{}).Resolve()
	if ent.Status != StatusAbsent {
		t.Fatalf("status = %q, want absent", ent.Status)
	}
	if ent.Allows(FeatureSignedBundles) {
		t.Error("OSS build must not grant any feature")
	}
	if ent.Message() != "" {
		t.Error("absent license must be silent")
	}
}

func TestResolve_NoTokenFoundIsAbsent(t *testing.T) {
	pub, _ := newKeypair(t)
	r := &Resolver{
		Keys:        map[string]ed25519.PublicKey{testKID: pub},
		Getenv:      func(string) string { return "" },
		ConfigPaths: []string{filepath.Join(t.TempDir(), "does-not-exist")},
	}
	if got := r.Resolve().Status; got != StatusAbsent {
		t.Fatalf("status = %q, want absent", got)
	}
}

func TestNilEntitlementIsFailOpenSafe(t *testing.T) {
	var e *Entitlement
	if e.Allows(FeatureSignedBundles) {
		t.Error("nil entitlement must not allow features")
	}
	if e.Active() {
		t.Error("nil entitlement must not be active")
	}
	if e.Message() != "" {
		t.Error("nil entitlement message must be empty")
	}
}

func TestResolve_SchemaVersionMismatchIsInvalid(t *testing.T) {
	pub, priv := newKeypair(t)
	claim := validClaim()
	claim.V = SchemaVersion + 1
	token := signToken(t, priv, testKID, claim)

	ent := resolverFor(pub, token, refNow()).Resolve()
	if ent.Status != StatusInvalid || ent.Reason != "unsupported schema version" {
		t.Fatalf("status=%q reason=%q, want invalid/unsupported schema version", ent.Status, ent.Reason)
	}
}

func TestResolve_Base64EnvAndRawFileBothWork(t *testing.T) {
	pub, priv := newKeypair(t)
	token := signToken(t, priv, testKID, validClaim())

	// Env delivered as base64 of the envelope JSON.
	b64 := base64.RawURLEncoding.EncodeToString(token)
	envResolver := resolverFor(pub, []byte(b64), refNow())
	if s := envResolver.Resolve().Status; s != StatusActive {
		t.Errorf("base64 env token: status %q, want active", s)
	}

	// File delivered as raw JSON via ExplicitPath.
	dir := t.TempDir()
	path := filepath.Join(dir, "license")
	if err := os.WriteFile(path, token, 0o600); err != nil {
		t.Fatal(err)
	}
	fileResolver := &Resolver{
		Keys:         map[string]ed25519.PublicKey{testKID: pub},
		Now:          refNow,
		Getenv:       func(string) string { return "" },
		ExplicitPath: path,
	}
	if s := fileResolver.Resolve().Status; s != StatusActive {
		t.Errorf("raw file token: status %q, want active", s)
	}
}

func TestResolve_MalformedTokenIsInvalidNotPanic(t *testing.T) {
	pub, _ := newKeypair(t)
	for _, garbage := range []string{"not json not base64 %%%", "{", "{}"} {
		ent := resolverFor(pub, []byte(garbage), refNow()).Resolve()
		if ent.Status != StatusInvalid {
			t.Errorf("garbage %q: status %q, want invalid", garbage, ent.Status)
		}
		if ent.Allows(FeatureSignedBundles) {
			t.Errorf("garbage %q must not grant features", garbage)
		}
	}
}

func TestDefaultConfigPaths_Ordering(t *testing.T) {
	getenv := func(k string) string {
		switch k {
		case "XDG_CONFIG_HOME":
			return "/xdg"
		case "HOME":
			return "/home/u"
		}
		return ""
	}
	paths := DefaultConfigPaths(getenv)
	if len(paths) != 2 || paths[0] != filepath.Join("/xdg", "pkgsafe", "license") {
		t.Fatalf("XDG should win: %v", paths)
	}

	getenvNoXDG := func(k string) string {
		if k == "HOME" {
			return "/home/u"
		}
		return ""
	}
	paths = DefaultConfigPaths(getenvNoXDG)
	if paths[0] != filepath.Join("/home/u", ".config", "pkgsafe", "license") {
		t.Fatalf("HOME fallback expected: %v", paths)
	}
}
