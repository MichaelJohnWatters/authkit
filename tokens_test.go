package authkit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var testKey = []byte(strings.Repeat("k", 32))

func TestNewTokenService_RejectsWeakKey(t *testing.T) {
	if _, err := NewTokenService([]byte("short")); !errors.Is(err, ErrWeakSigningKey) {
		t.Fatalf("got %v want ErrWeakSigningKey", err)
	}
}

func TestAccessToken_RoundTrip(t *testing.T) {
	ts, _ := NewTokenService(testKey)
	tok, err := ts.IssueAccess("user-1", 3, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if uid, sv, err := ts.VerifyAccess(tok); err != nil || uid != "user-1" || sv != 3 {
		t.Fatalf("verify: uid=%q err=%v", uid, err)
	}
}

func TestAccessToken_Rejects(t *testing.T) {
	ts, _ := NewTokenService(testKey)
	other, _ := NewTokenService([]byte(strings.Repeat("x", 32)))

	expired, _ := ts.IssueAccess("u", 0, time.Minute, time.Now().Add(-time.Hour))
	foreign, _ := other.IssueAccess("u", 0, time.Hour, time.Now())
	// alg=none must never be accepted (alg-confusion guard).
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
		Subject: "u", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	noSubject, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(testKey)

	noExpiry, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "u",
	}).SignedString(testKey)

	for name, tok := range map[string]string{
		"expired": expired, "wrong key": foreign, "alg none": none,
		"no subject": noSubject, "no expiry": noExpiry, "garbage": "not.a.jwt",
	} {
		if _, _, err := ts.VerifyAccess(tok); !errors.Is(err, ErrSessionInvalid) {
			t.Errorf("%s: got %v want ErrSessionInvalid", name, err)
		}
	}
}

func TestPassword_HashAndCheck(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("short: got %v", err)
	}
	if _, err := HashPassword(strings.Repeat("p", 73)); !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("long: got %v", err)
	}
	h, err := HashPassword("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPassword(h, "correct-horse"); err != nil {
		t.Errorf("match: %v", err)
	}
	if err := CheckPassword(h, "wrong-horse"); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("mismatch: got %v", err)
	}
	// DummyHash must be a well-formed hash, or the timing-equalisation path
	// returns early and leaks which emails exist.
	if err := CheckPassword(DummyHash, "anything"); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("DummyHash malformed: %v", err)
	}
}

func TestSignValue_RoundTripAndTamper(t *testing.T) {
	ts, err := NewTokenService([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	tok := ts.SignValue("unsubscribe", "user_123-AB")
	if v, ok := ts.VerifyValue("unsubscribe", tok); !ok || v != "user_123-AB" {
		t.Fatalf("round trip: %q %v", v, ok)
	}
	if _, ok := ts.VerifyValue("other-purpose", tok); ok {
		t.Error("a token for one purpose must not verify for another")
	}
	if _, ok := ts.VerifyValue("unsubscribe", "someone_else"+tok[strings.Index(tok, "."):]); ok {
		t.Error("changing the value must break the signature")
	}
	if _, ok := ts.VerifyValue("unsubscribe", "garbage"); ok {
		t.Error("garbage verified")
	}
}
