# authkit

The stateless half of hand-rolled email/password auth, shared by
[kickstand](https://github.com/MichaelJohnWatters/kickstand) and
[yoga-school](https://github.com/MichaelJohnWatters/yoga-school).

| What | Where |
|---|---|
| bcrypt cost 12, 8–72 byte passwords, timing-equalising `DummyHash` | `password.go`, `errors.go` |
| NCSC 100k-most-used list (≈46.5k entries ≥ 8 chars), `IsCommonPassword` | `common_passwords.go` |
| HS256 access tokens: `sub`/`iat`/`nbf`/`exp` + `sv` session version, `kid` header, previous keys still verify, `exp` required, alg-confusion guard | `tokens.go` |
| `SignValue`/`VerifyValue` — HMAC-signed values for stateless links (unsubscribe) | `tokens.go` |
| `NewOpaqueToken`/`HashOpaqueToken` — 256-bit refresh/reset tokens, store only the hash | `tokens.go` |
| TOTP (RFC 6238, ±1 step, replay-safe via last step), otpauth URL, recovery codes | `totp.go` |
| AES-256-GCM `Sealer` for at-rest secrets (`SealerFromEnv(name)`, `NewSealer(hex)`) | `secrets/` |

**Not here, on purpose:** anything with a database — refresh-token families
and reuse detection, session versions, lockout counters, MFA challenges,
per-role session lifetimes. Each app owns those against its own schema.

## Use

```go
import (
	auth "github.com/MichaelJohnWatters/authkit"
	"github.com/MichaelJohnWatters/authkit/secrets"
)

ts, err := auth.NewTokenService(key, previousKey) // each ≥ 32 bytes
tok, _ := ts.IssueAccess(userID, sessionVersion, time.Hour, time.Now())
uid, sv, err := ts.VerifyAccess(tok)
```

Releases are tagged `vX.Y.Z`; bump with `go get github.com/MichaelJohnWatters/authkit@vX.Y.Z`.

## Going private

The repo is public for now. When it flips to private, every consumer needs:

- local: `go env -w GOPRIVATE=github.com/MichaelJohnWatters/*` (git over SSH
  already authenticates).
- CI: a read-only token for this repo, e.g. a fine-grained PAT stored as
  `AUTHKIT_TOKEN`, then
  `git config --global url."https://x-access-token:${AUTHKIT_TOKEN}@github.com/".insteadOf "https://github.com/"`
  and `GOPRIVATE` before `go mod download`.
- Docker builds: pass the same token as a BuildKit secret
  (`--secret id=gh,env=AUTHKIT_TOKEN`), never as a build arg, or run
  `go mod vendor` before building.

## Credits

`common_passwords.txt.gz` is derived from `100k-most-used-passwords-NCSC.txt`
in [SecLists](https://github.com/danielmiessler/SecLists) (MIT).
