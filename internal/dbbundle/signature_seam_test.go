package dbbundle

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

// writeSignedBundle builds a structurally valid bundle carrying a signature.sig
// file and returns its path. The signature bytes are opaque here — verification
// is the injected SignatureVerifier's job.
func writeSignedBundle(t *testing.T, sig []byte) string {
	t.Helper()
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		BundleKind:    BundleKind,
		Signature:     SignatureInfo{Present: true, Algorithm: "ed25519"},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	db := []byte("SQLite format 3\x00 fake db payload")
	files := map[string][]byte{
		ManifestPath: manifestBytes,
		DBPathInZip:  db,
	}
	// Checksums cover manifest + db only (Verify excludes checksums + signature).
	files[ChecksumsPath] = checksumsFor(map[string][]byte{ManifestPath: manifestBytes, DBPathInZip: db})
	files[SignaturePath] = sig

	path := filepath.Join(t.TempDir(), "signed.zip")
	if err := writeZip(path, files); err != nil {
		t.Fatal(err)
	}
	return path
}

// restoreVerifier resets the package hook after a test.
func restoreVerifier(t *testing.T) {
	t.Helper()
	prev := SignatureVerifier
	t.Cleanup(func() { SignatureVerifier = prev })
}

func TestVerify_SignedBundle_OSSDefaultByteIdentical(t *testing.T) {
	restoreVerifier(t)
	SignatureVerifier = nil // OSS build

	path := writeSignedBundle(t, []byte("opaque-signature"))
	res, err := Verify(path)
	want := "signed offline intelligence bundles are private-enterprise functionality"
	if err == nil || err.Error() != want {
		t.Fatalf("Verify = %v, want %q", err, want)
	}
	if !res.SignaturePresent {
		t.Error("SignaturePresent should be true")
	}
	if res.SignatureChecked || res.SignatureVerified {
		t.Error("OSS build must not mark the signature checked/verified")
	}
}

func TestVerify_SignedBundle_HookVerifies(t *testing.T) {
	restoreVerifier(t)
	var gotSig []byte
	SignatureVerifier = func(files map[string][]byte, m Manifest) (bool, error) {
		gotSig = files[SignaturePath]
		return true, nil
	}

	path := writeSignedBundle(t, []byte("good-sig"))
	res, err := Verify(path)
	if err != nil {
		t.Fatalf("expected nil error when hook verifies, got %v", err)
	}
	if !res.SignatureChecked || !res.SignatureVerified {
		t.Errorf("expected checked+verified, got checked=%v verified=%v", res.SignatureChecked, res.SignatureVerified)
	}
	if string(gotSig) != "good-sig" {
		t.Errorf("hook received sig %q, want good-sig", gotSig)
	}
}

func TestVerify_SignedBundle_HookRejects_FailClosed(t *testing.T) {
	restoreVerifier(t)
	SignatureVerifier = func(map[string][]byte, Manifest) (bool, error) {
		return false, nil // signature does not verify
	}

	path := writeSignedBundle(t, []byte("bad-sig"))
	res, err := Verify(path)
	if err == nil || err.Error() != "bundle signature verification failed" {
		t.Fatalf("Verify = %v, want fail-closed rejection", err)
	}
	if !res.SignatureChecked || res.SignatureVerified {
		t.Error("expected checked=true, verified=false")
	}
}

func TestVerify_SignedBundle_HookError(t *testing.T) {
	restoreVerifier(t)
	boom := errors.New("key unavailable")
	SignatureVerifier = func(map[string][]byte, Manifest) (bool, error) {
		return false, boom
	}

	path := writeSignedBundle(t, []byte("x"))
	_, err := Verify(path)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("Verify = %v, want wrapped hook error", err)
	}
}

func TestImport_SignedBundle_RejectedInOSS(t *testing.T) {
	restoreVerifier(t)
	SignatureVerifier = nil

	path := writeSignedBundle(t, []byte("sig"))
	target := filepath.Join(t.TempDir(), "out.db")
	if _, err := Import(path, target); err == nil {
		t.Fatal("expected signed bundle import to be rejected in OSS build")
	}
}

// TestVerify_UnsignedBundle_UnaffectedByHook confirms the seam only engages when
// a signature is present.
func TestVerify_UnsignedBundle_UnaffectedByHook(t *testing.T) {
	restoreVerifier(t)
	called := false
	SignatureVerifier = func(map[string][]byte, Manifest) (bool, error) {
		called = true
		return false, errors.New("should not be called")
	}

	manifest := Manifest{SchemaVersion: SchemaVersion, BundleKind: BundleKind}
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	db := []byte("SQLite format 3\x00 payload")
	files := map[string][]byte{ManifestPath: mb, DBPathInZip: db}
	files[ChecksumsPath] = checksumsFor(map[string][]byte{ManifestPath: mb, DBPathInZip: db})
	path := filepath.Join(t.TempDir(), "unsigned.zip")
	if err := writeZip(path, files); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatalf("unsigned bundle should verify cleanly, got %v", err)
	}
	if called {
		t.Error("SignatureVerifier must not be called for unsigned bundles")
	}
	if res.SignaturePresent {
		t.Error("SignaturePresent should be false")
	}
}
