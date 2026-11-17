// Package authkit holds the stateless, app-neutral pieces of hand-rolled
// email/password auth shared by the portfolio's Go servers: bcrypt password
// hashing and policy (length + NCSC common-password list), HS256 access
// tokens with signing-key rotation and a session-version claim, opaque
// refresh/reset tokens, HMAC-signed values, and TOTP two-step codes with
// recovery codes. Subpackage secrets is AES-256-GCM at-rest encryption.
//
// Anything that touches a database — refresh-token families, lockout
// counters, session versions, MFA challenges — lives in each app, because
// each app's schema differs.
package authkit
