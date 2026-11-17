package authkit

import "errors"

// MinPasswordLength is the minimum accepted password length (bytes).
const MinPasswordLength = 8

var (
	ErrInvalidCredential = errors.New("auth: invalid email or password")
	ErrAccountDisabled   = errors.New("auth: account is disabled")
	ErrSessionInvalid    = errors.New("auth: session is invalid, expired, or revoked")
	ErrProfileMissing    = errors.New("auth: no local profile for this identity")
	ErrPasswordTooShort  = errors.New("auth: password too short")
	ErrPasswordTooLong   = errors.New("auth: password too long")
	ErrWeakSigningKey    = errors.New("auth: token signing key must be at least 32 bytes")
)
