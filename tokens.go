package authkit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// TokenService mints and verifies short-lived access tokens. Tokens are HS256 JWTs carrying only the
// user id (subject) + expiry; the middleware re-loads the authoritative user
// (role, deactivated, email) from the DB on each request, so a disabled or
// role-changed account takes effect immediately and nothing stale is trusted
// from the token itself.
//
// It signs with one key and also accepts the keys it's given as previous
// ones, so the key can be changed without every signed-in phone's token, or
// every unsubscribe link already emailed, failing at once: swap the new key
// in, keep the old one as previous until those have aged out (an hour for
// tokens; unsubscribe links last as long as the old key is kept).
type TokenService struct {
	keys []signingKey // keys[0] signs; all of them verify
}

type signingKey struct {
	id     string // "kid" in the token header: which key signed it
	secret []byte
}

// NewTokenService builds a service from a signing secret (≥32 bytes), plus
// any previous secrets still accepted. Supply them from a secret store / env
// in production, never hardcoded values.
func NewTokenService(secret []byte, previous ...[]byte) (*TokenService, error) {
	t := &TokenService{}
	for _, k := range append([][]byte{secret}, previous...) {
		if len(k) < 32 {
			return nil, ErrWeakSigningKey
		}
		t.keys = append(t.keys, signingKey{id: keyID(k), secret: k})
	}
	return t, nil
}

// keyID names a key without giving anything of it away: the start of a
// hash of it.
func keyID(secret []byte) string {
	sum := sha256.Sum256(append([]byte("authkit kid\x00"), secret...))
	return hex.EncodeToString(sum[:6])
}

// accessClaims: the registered claims plus the user's session version at
// issue time. The middleware rejects a token whose version is behind the
// user's current one, which is how ending sessions cuts off access tokens
// that haven't expired yet.
type accessClaims struct {
	jwt.RegisteredClaims
	SessionVersion int `json:"sv"`
}

// IssueAccess returns a signed access token for userID at sessionVersion,
// valid for ttl from now.
func (t *TokenService) IssueAccess(userID string, sessionVersion int, ttl time.Duration, now time.Time) (string, error) {
	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		SessionVersion: sessionVersion,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = t.keys[0].id
	return tok.SignedString(t.keys[0].secret)
}

// VerifyAccess validates signature + expiry and returns the subject (user id)
// and session version. Returns ErrSessionInvalid for anything wrong — bad
// signature, expired, no expiry at all, malformed, or a non-HMAC algorithm
// (guards against alg-confusion attacks).
//
// The header's kid picks the key; a token from before kids (or naming no key
// we hold) is tried against each.
func (t *TokenService) VerifyAccess(tokenStr string) (userID string, sessionVersion int, err error) {
	for _, k := range t.candidates(tokenStr) {
		claims := &accessClaims{}
		_, err = jwt.ParseWithClaims(tokenStr, claims, func(tok *jwt.Token) (any, error) {
			if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", tok.Header["alg"])
			}
			return k.secret, nil
		})
		// jwt v4 treats exp as optional; ours always carry one, so a token
		// without it wasn't minted here.
		if err == nil && claims.Subject != "" && claims.ExpiresAt != nil {
			return claims.Subject, claims.SessionVersion, nil
		}
	}
	return "", 0, ErrSessionInvalid
}

// candidates: the key a token's header names, or every key when it names
// none we hold.
func (t *TokenService) candidates(tokenStr string) []signingKey {
	var head struct {
		Kid string `json:"kid"`
	}
	if h, _, ok := strings.Cut(tokenStr, "."); ok {
		if b, err := base64.RawURLEncoding.DecodeString(h); err == nil {
			_ = json.Unmarshal(b, &head)
		}
	}
	for _, k := range t.keys {
		if head.Kid != "" && k.id == head.Kid {
			return []signingKey{k}
		}
	}
	return t.keys
}

// SignValue returns "value.mac": value plus an HMAC-SHA256 over purpose and
// value, keyed by the signing secret. For links that must keep working
// indefinitely with nothing stored (an email's unsubscribe link). value must
// not contain ".".
func (t *TokenService) SignValue(purpose, value string) string {
	return value + "." + base64.RawURLEncoding.EncodeToString(mac(t.keys[0].secret, purpose, value))
}

// VerifyValue checks a SignValue token for purpose and returns the value.
func (t *TokenService) VerifyValue(purpose, token string) (string, bool) {
	value, sig, ok := strings.Cut(token, ".")
	if !ok || value == "" {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", false
	}
	for _, k := range t.keys {
		if hmac.Equal(got, mac(k.secret, purpose, value)) {
			return value, true
		}
	}
	return "", false
}

func mac(secret []byte, purpose, value string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(purpose + "\x00" + value))
	return m.Sum(nil)
}

// NewOpaqueToken returns a 256-bit URL-safe random token for password-reset and
// refresh tokens. Store a hash of it (not the token) with an expiry.
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashOpaqueToken returns the SHA-256 hex of an opaque token — only the hash is
// stored, so a DB leak can't be replayed to reset passwords or refresh sessions.
func HashOpaqueToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
