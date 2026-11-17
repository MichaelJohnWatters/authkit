package authkit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Changing the signing key: what the old key signed still verifies while
// it's kept as a previous key, and stops once it's dropped.
func TestTokenService_KeyRotation(t *testing.T) {
	oldKey, newKey := []byte(strings.Repeat("o", 32)), []byte(strings.Repeat("n", 32))
	before, _ := NewTokenService(oldKey)
	rotated, err := NewTokenService(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := NewTokenService(newKey)

	tok, _ := before.IssueAccess("u", 2, time.Hour, time.Now())
	if uid, sv, err := rotated.VerifyAccess(tok); err != nil || uid != "u" || sv != 2 {
		t.Errorf("old key's token with the old key kept: uid=%q sv=%d err=%v", uid, sv, err)
	}
	if _, _, err := after.VerifyAccess(tok); !errors.Is(err, ErrSessionInvalid) {
		t.Errorf("old key's token once it's dropped: got %v want ErrSessionInvalid", err)
	}
	link := before.SignValue("unsubscribe", "u")
	if v, ok := rotated.VerifyValue("unsubscribe", link); !ok || v != "u" {
		t.Error("an emailed link signed with the old key stopped working while it's kept")
	}
	if _, ok := after.VerifyValue("unsubscribe", link); ok {
		t.Error("an emailed link signed with a dropped key still works")
	}

	// New tokens are signed with the new key and say so.
	fresh, _ := rotated.IssueAccess("u", 2, time.Hour, time.Now())
	if _, _, err := after.VerifyAccess(fresh); err != nil {
		t.Errorf("new token isn't signed with the new key: %v", err)
	}
	parsed, _, _ := jwt.NewParser().ParseUnverified(fresh, jwt.MapClaims{})
	if kid := parsed.Header["kid"]; kid != keyID(newKey) {
		t.Errorf("kid = %v, want the new key's id %q", kid, keyID(newKey))
	}

	// A token from before kids carries none: still checked against each key.
	noKid, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "u", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString(oldKey)
	if _, _, err := rotated.VerifyAccess(noKid); err != nil {
		t.Errorf("token without a kid: %v", err)
	}

	if _, err := NewTokenService(newKey, []byte("short")); !errors.Is(err, ErrWeakSigningKey) {
		t.Errorf("weak previous key: got %v want ErrWeakSigningKey", err)
	}
}
