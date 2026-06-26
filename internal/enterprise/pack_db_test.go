package enterprise_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/niyam-ai/pkgsafe/internal/db"
	"github.com/niyam-ai/pkgsafe/internal/enterprise"
)

// TestPackBundledDBNotApplied asserts that installing a policy pack which
// bundles a pkgsafe.db never replaces the active vulnerability database — the
// bundled DB is quarantined inside the pack's install directory instead.
func TestPackBundledDBNotApplied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Seed a legitimate active DB so we can prove it survives untouched.
	activeDB := db.DefaultDBPath()
	if err := os.MkdirAll(filepath.Dir(activeDB), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("REAL-VULN-DB")
	if err := os.WriteFile(activeDB, original, 0o644); err != nil {
		t.Fatal(err)
	}

	meta := `{"schema_version":"1.0","name":"pkg-with-db","version":"2026.06.01","owner":"X","expires_at":"2030-12-31T23:59:59Z","compatibility":{"min_pkgsafe_version":"0.1.0"}}`
	malicious := []byte("MALICIOUS-EMPTY-DB")

	files := map[string][]byte{
		"metadata.json": []byte(meta),
		"pkgsafe.db":    malicious,
	}
	var cs bytes.Buffer
	for _, fname := range []string{"metadata.json", "pkgsafe.db"} {
		sum := sha256.Sum256(files[fname])
		fmt.Fprintf(&cs, "%s  %s\n", hex.EncodeToString(sum[:]), fname)
	}
	files["checksums.txt"] = cs.Bytes()

	packPath := createTestTarGz(t, files)
	if err := enterprise.InstallPolicyPack(packPath); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// The active DB must be byte-for-byte unchanged.
	got, err := os.ReadFile(activeDB)
	if err != nil {
		t.Fatalf("active DB missing after install: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("pack overwrote the active vulnerability DB: got %q", got)
	}

	// The bundled DB must be quarantined inside the pack's install dir.
	quarantined := filepath.Join(enterprise.GetPolicyPacksDir(), "pkg-with-db", "2026.06.01", "pkgsafe.db")
	q, err := os.ReadFile(quarantined)
	if err != nil {
		t.Fatalf("expected bundled DB quarantined in pack dir: %v", err)
	}
	if !bytes.Equal(q, malicious) {
		t.Fatalf("quarantined DB content mismatch")
	}
}
