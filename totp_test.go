package authkit

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA1, secret "12345678901234567890"),
// truncated to 6 digits.
func TestTOTPCode_RFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		got, err := TOTPCode(secret, TOTPStep(time.Unix(c.unix, 0)))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("t=%d: got %s want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyTOTP_SkewAndReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	cur := TOTPStep(now)
	code := func(step int64) string { c, _ := TOTPCode(secret, step); return c }

	step, ok := VerifyTOTP(secret, code(cur-1), now, 0)
	if !ok || step != cur-1 {
		t.Fatalf("previous step's code should verify (got %d, %v)", step, ok)
	}
	if _, ok := VerifyTOTP(secret, code(cur-1), now, step); ok {
		t.Error("a code must not verify twice")
	}
	if _, ok := VerifyTOTP(secret, code(cur+1), now, step); !ok {
		t.Error("next step's code should verify")
	}
	if _, ok := VerifyTOTP(secret, code(cur-2), now, 0); ok {
		t.Error("a code two steps old should not verify")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Error("a 5-digit code should not verify")
	}
	c := code(cur)
	if _, ok := VerifyTOTP(secret, c[:3]+" "+c[3:], now, 0); !ok {
		t.Error("a code typed with a space should verify")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 14 || strings.Count(c, "-") != 2 {
			t.Errorf("unexpected code shape %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
	}
	if HashRecoveryCode(codes[0]) != HashRecoveryCode(" "+strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))+" ") {
		t.Error("recovery codes should match regardless of case, spaces and dashes")
	}
}

func TestTOTPURL(t *testing.T) {
	u := TOTPURL("Studio 52", "maya@studio52.dev", "ABC")
	if !strings.HasPrefix(u, "otpauth://totp/Studio%2052:maya@studio52.dev?") || !strings.Contains(u, "secret=ABC") || !strings.Contains(u, "issuer=Studio+52") {
		t.Errorf("url = %s", u)
	}
}
