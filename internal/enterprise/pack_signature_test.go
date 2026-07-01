package enterprise_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sairintechnologycom/pkgsafe/internal/enterprise"
)

// signedPackSrc writes a minimal valid pack source dir and returns its path.
func signedPackSrc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	meta := `{"schema_version":"1.0","name":"signed-pack","version":"2026.06.01","owner":"Sec","expires_at":"2030-12-31T23:59:59Z","compatibility":{"min_pkgsafe_version":"0.1.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newKeypair writes a private key to disk and returns its path plus the public key.
func newKeypair(t *testing.T) (privPath string, pub ed25519.PublicKey) {
	t.Helper()
	privPEM, pubPEM, err := enterprise.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(t.TempDir(), "pack.key")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err = enterprise.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return privPath, pub
}

func cloneFiles(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func rebuildChecksums(files map[string][]byte) []byte {
	var b []byte
	for fname, content := range files {
		if fname == "checksums.txt" || fname == "signature.sig" {
			continue
		}
		sum := sha256.Sum256(content)
		b = append(b, []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), fname))...)
	}
	return b
}

func TestKeypairRoundTrip(t *testing.T) {
	privPEM, pubPEM, err := enterprise.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := enterprise.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	pub, err := enterprise.ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	msg := []byte("checksums-content")
	sig := enterprise.SignPack(priv, msg)
	if err := enterprise.VerifyPackSignature([]ed25519.PublicKey{pub}, msg, sig); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
	// tampered message must fail
	if err := enterprise.VerifyPackSignature([]ed25519.PublicKey{pub}, []byte("other"), sig); err == nil {
		t.Fatal("expected verify failure on tampered message")
	}
	// empty trust set must fail closed
	if err := enterprise.VerifyPackSignature(nil, msg, sig); err == nil {
		t.Fatal("expected verify failure with no trusted keys")
	}
}

func TestSignedPackVerifiesWithTrustedKey(t *testing.T) {
	src := signedPackSrc(t)
	privPath, pub := newKeypair(t)
	out := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := enterprise.CreatePolicyPack("signed-pack", src, out, privPath); err != nil {
		t.Fatalf("create signed pack: %v", err)
	}

	// Correct trusted key verifies.
	if _, err := enterprise.VerifyPolicyPackWithKeys(out, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("expected verify success, got %v", err)
	}

	// A different key must be rejected.
	_, otherPub := newKeypair(t)
	if _, err := enterprise.VerifyPolicyPackWithKeys(out, []ed25519.PublicKey{otherPub}); err == nil {
		t.Fatal("expected verify failure with wrong key")
	}

	// Signing required + no trusted key => fail closed.
	if _, err := enterprise.VerifyPolicyPackWithKeys(out, nil); err == nil {
		t.Fatal("expected fail-closed when a signed-required pack has no trusted key")
	}
}

func TestSignedPackTamperDetected(t *testing.T) {
	src := signedPackSrc(t)
	privPath, pub := newKeypair(t)
	out := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := enterprise.CreatePolicyPack("signed-pack", src, out, privPath); err != nil {
		t.Fatal(err)
	}
	files, err := enterprise.VerifyPolicyPackWithKeys(out, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}

	// Case A: change content but keep original checksums + signature.
	// The checksum check catches it.
	a := cloneFiles(files)
	a["metadata.json"] = append(a["metadata.json"], ' ') // still valid JSON, different bytes
	pathA := createTestTarGz(t, a)
	if _, err := enterprise.VerifyPolicyPackWithKeys(pathA, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected checksum mismatch on tampered content")
	}

	// Case B: change content AND recompute checksums.txt, but keep the stale
	// signature. The signature no longer matches the new checksums => fail.
	b := cloneFiles(files)
	b["metadata.json"] = append(b["metadata.json"], ' ')
	b["checksums.txt"] = rebuildChecksums(b)
	pathB := createTestTarGz(t, b)
	if _, err := enterprise.VerifyPolicyPackWithKeys(pathB, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected signature failure when checksums updated but signature stale")
	}
}

func TestUnsignedPackStillVerifies(t *testing.T) {
	src := signedPackSrc(t)
	out := filepath.Join(t.TempDir(), "pack.tar.gz")
	// No signing key: pack is unsigned, signing not required.
	if err := enterprise.CreatePolicyPack("signed-pack", src, out, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := enterprise.VerifyPolicyPackWithKeys(out, nil); err != nil {
		t.Fatalf("unsigned pack should verify without keys, got %v", err)
	}
}
