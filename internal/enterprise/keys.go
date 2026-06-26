package enterprise

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SignatureAlgorithm is the only signing algorithm PkgSafe currently supports
// for policy packs. The pack metadata's signing.algorithm field is validated
// against this value during verification.
const SignatureAlgorithm = "ed25519"

// TrustedKeysEnv is a PathListSeparator-delimited list of public-key files
// trusted to sign policy packs.
const TrustedKeysEnv = "PKGSAFE_PACK_PUBLIC_KEYS"

// GenerateKeypair returns a fresh ed25519 keypair, PEM-encoded as PKCS#8
// (private) and PKIX/SubjectPublicKeyInfo (public).
func GenerateKeypair() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM, nil
}

// LoadPrivateKey reads an ed25519 private key from a PEM (PKCS#8) file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	return ParsePrivateKey(data)
}

// ParsePrivateKey decodes an ed25519 private key from PEM-encoded PKCS#8 bytes.
func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signing key is not valid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not an ed25519 key")
	}
	return priv, nil
}

// LoadPublicKey reads an ed25519 public key from a PEM (PKIX) file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	return ParsePublicKey(data)
}

// ParsePublicKey decodes an ed25519 public key from PEM-encoded PKIX bytes.
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("public key is not valid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ed25519 key")
	}
	return pub, nil
}

// SignPack produces a detached ed25519 signature over the pack's checksums.txt
// content. Because checksums.txt covers every other file by SHA-256, a valid
// signature over it authenticates the entire pack.
func SignPack(priv ed25519.PrivateKey, checksums []byte) []byte {
	return ed25519.Sign(priv, checksums)
}

// VerifyPackSignature reports nil if sig is a valid signature over checksums by
// any of the trusted keys. It returns an error if no trusted key matches.
func VerifyPackSignature(trustedKeys []ed25519.PublicKey, checksums, sig []byte) error {
	if len(trustedKeys) == 0 {
		return fmt.Errorf("no trusted public key configured")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed signature: expected %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	for _, pub := range trustedKeys {
		if len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, checksums, sig) {
			return nil
		}
	}
	return fmt.Errorf("signature does not match any trusted key")
}

// DefaultTrustedKeys loads the set of public keys trusted to sign policy packs,
// from the PKGSAFE_PACK_PUBLIC_KEYS env var (a PathListSeparator-delimited list
// of files) and from every file in ~/.pkgsafe/trusted-keys/. Unparseable files
// are skipped silently so an unrelated file in the directory can't break trust
// resolution; an empty result simply means nothing is trusted (fail closed).
func DefaultTrustedKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey

	if env := os.Getenv(TrustedKeysEnv); env != "" {
		for _, p := range strings.Split(env, string(os.PathListSeparator)) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if k, err := LoadPublicKey(p); err == nil {
				keys = append(keys, k)
			}
		}
	}

	dir := TrustedKeysDir()
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if k, err := LoadPublicKey(filepath.Join(dir, e.Name())); err == nil {
				keys = append(keys, k)
			}
		}
	}

	return keys
}

// TrustedKeysDir is the on-disk directory of trusted public keys.
func TrustedKeysDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home == "" {
		return filepath.Join(".pkgsafe", "trusted-keys")
	}
	return filepath.Join(home, ".pkgsafe", "trusted-keys")
}
