// Package secrets is the envelope-encryption helper for at-rest sensitive
// columns (API keys, TOTP secrets). Every encrypted blob is independently
// keyed with a fresh nonce and bound to a single master key: 32 raw bytes,
// hex-encoded, usually supplied via an env var the app names.
//
// Why a package, not inline:
//   - Centralises the "where does the master key come from" question to one
//     file so future rotation / KMS migration is local.
//   - Lets multiple secret tables share the same primitives (future:
//     mailer creds, SMS gateway, etc.) without copy-pasting AES-GCM
//     ceremony.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrNoMasterKey is returned when callers try to encrypt/decrypt without a
// master key configured. Server startup should refuse to boot when an
// encrypted row exists but the key is missing.
var ErrNoMasterKey = errors.New("secrets: no master key configured")

// Sealer encrypts and decrypts short strings with AES-256-GCM. Created
// once at startup; safe for concurrent use.
type Sealer struct {
	aead cipher.AEAD
}

// SealerFromEnv reads the hex master key from env var name and constructs
// the Sealer. Returns (nil, nil) when unset — the server keeps booting;
// calls to Encrypt/Decrypt later fail loudly with ErrNoMasterKey.
//
// Apps that must not run without it check `sealer == nil` at startup (e.g.
// when encrypted rows already exist) and abort, so an ops misconfig is
// impossible to miss.
func SealerFromEnv(name string) (*Sealer, error) {
	hexKey := os.Getenv(name)
	if hexKey == "" {
		return nil, nil
	}
	s, err := NewSealer(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return s, nil
}

// NewSealer builds a Sealer from a 64-hex-char (32-byte) master key.
func NewSealer(hexKey string) (*Sealer, error) {
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("master key must be hex: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("master key must decode to 32 bytes, got %d", len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Encrypt returns (ciphertext, nonce). Both are stored separately so the
// nonce can be inspected for uniqueness in audits if desired. Each call
// generates a fresh random nonce — never reuse a (key, nonce) pair, hence
// no "encrypt with this nonce" overload.
func (s *Sealer) Encrypt(plain string) (ciphertext, nonce []byte, err error) {
	if s == nil {
		return nil, nil, ErrNoMasterKey
	}
	nonce = make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext = s.aead.Seal(nil, nonce, []byte(plain), nil)
	return ciphertext, nonce, nil
}

// Decrypt is the inverse of Encrypt. Returns the plaintext or an auth error
// if the ciphertext was tampered with.
func (s *Sealer) Decrypt(ciphertext, nonce []byte) (string, error) {
	if s == nil {
		return "", ErrNoMasterKey
	}
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plain), nil
}

// Available reports whether a master key was loaded. Cheap predicate for
// callers that want to surface "encryption not configured" cleanly instead
// of erroring on every read.
func (s *Sealer) Available() bool { return s != nil }

// ---- test helpers --------------------------------------------------

var testSealerOnce sync.Once
var testSealer *Sealer

// NewTestSealer constructs a Sealer with a fixed key. Tests in this
// package and any consumer that needs to round-trip a value can call this
// instead of fiddling with env vars.
func NewTestSealer() *Sealer {
	testSealerOnce.Do(func() {
		raw := make([]byte, 32)
		// Deterministic so test failures are reproducible.
		for i := range raw {
			raw[i] = byte(i + 1)
		}
		block, _ := aes.NewCipher(raw)
		aead, _ := cipher.NewGCM(block)
		testSealer = &Sealer{aead: aead}
	})
	return testSealer
}
