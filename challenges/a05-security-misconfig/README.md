# A05: Security Misconfiguration

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A small internal-looking app. Nothing obviously exploitable on the homepage —
by design, this challenge doesn't tell you where to look. Two realistic,
tool-free ways to find it, no wordlist or scanner needed:

- **View page source.** There's a leftover developer comment mentioning
  exactly what shouldn't have shipped.
- **Check `/robots.txt`.** It disallows `/debug/` — meant to keep search
  engines from indexing it, which incidentally tells anyone who looks that
  something lives there.

## The bug

`GET /debug/config` — a diagnostics endpoint meant only for local development
— shipped enabled, with no authentication, in this build:

```go
// BUG: no authentication, and it should not exist in this build at all.
func debugConfigHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(internalConfig)
}
```

It dumps the app's internal configuration, including secrets.

## Exploit

```bash
curl -s http://localhost:9005/debug/config
```

## Flag

`CTF{a05_d3bug_m0d3_1n_pr0d}`

## The fix (for reference)

Debug/diagnostic endpoints should not exist in production builds at all —
gate them behind a build tag, an internal-only network boundary, and
authentication if they must exist anywhere reachable.
