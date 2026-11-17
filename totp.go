package authkit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) for two-factor sign-in: HMAC-SHA1, 30-second steps,
// 6 digits — the defaults every authenticator app (Google Authenticator,
// 1Password, Authy, …) assumes.

const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew accepts a code from one step either side of now, so a phone
	// clock that's a little off (or a code typed as it rolls over) still works.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 160-bit secret, base32-encoded (the form
// authenticator apps take).
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPStep is the time-step counter for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// TOTPCode returns the code for secret at the given step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("totp secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1_000_000), nil
}

// VerifyTOTP checks code against secret at now (± totpSkew steps). A code is
// only accepted for a step later than lastStep, so each code works once even
// within its 30 seconds. Returns the matched step, which the caller stores as
// the new lastStep.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	for step := cur - totpSkew; step <= cur+totpSkew; step++ {
		if step <= lastStep {
			continue
		}
		want, err := TOTPCode(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// TOTPURL is the otpauth:// URL an authenticator app scans as a QR code.
func TOTPURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// NewRecoveryCodes returns n one-time recovery codes like "k7qp-3xmd-w9ta"
// (60 bits each), for signing in when the authenticator is lost. Store only
// HashRecoveryCode of each.
func NewRecoveryCodes(n int) ([]string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o, 1/l/i
	out := make([]string, n)
	buf := make([]byte, 12)
	for i := range out {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j, b := range buf {
			if j > 0 && j%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(b)%len(alphabet)])
		}
		out[i] = sb.String()
	}
	return out, nil
}

// NormalizeRecoveryCode lowercases a typed recovery code and drops spaces and
// dashes, so "K7QP 3XMD W9TA" matches "k7qp-3xmd-w9ta".
func NormalizeRecoveryCode(code string) string {
	r := strings.NewReplacer("-", "", " ", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(code)))
}

// HashRecoveryCode is what's stored for a recovery code.
func HashRecoveryCode(code string) string {
	return HashOpaqueToken("recovery:" + NormalizeRecoveryCode(code))
}
