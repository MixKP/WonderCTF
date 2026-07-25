// Challenge a06-vulnerable-components — OWASP A06: Vulnerable and Outdated
// Components.
//
// ⚠️ INTENTIONALLY VULNERABLE. package.json pins lodash@4.17.4, which is
// vulnerable to prototype pollution via _.merge (CVE-2018-3721, fixed in
// 4.17.5) — a known, public CVE in an outdated dependency. This is a
// training target — never do this in real code; keep dependencies patched.
// See README.md.
'use strict'

const express = require('express')
const _ = require('lodash')

const FLAG = 'CTF{a06_kn0wn_cv3_1n_d3p}'
const PORT = process.env.PORT || 8080

const app = express()
app.use(express.json())

const defaultProfile = { theme: 'dark', notifications: true }

const PAGE_HTML = `<!doctype html>
<html>
<head><title>A06: Vulnerable Components — Old Dependency, New Exploit</title>
<style>
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A06: Vulnerable and Outdated Components</div>
  <h1>Profile Service</h1>
  <p>This service ships an outdated, known-vulnerable dependency.
     <code>POST /api/profile</code> merges your JSON body into a default profile.</p>
  <p><code>GET /api/flag</code> is admin-only.</p>
</body>
</html>`

app.get('/', (req, res) => {
  res.type('html').send(PAGE_HTML)
})

app.get('/healthz', (req, res) => {
  res.sendStatus(200)
})

// BUG: lodash@4.17.4's _.merge recursively assigns into "__proto__" keys
// instead of treating them as plain data, so a crafted request body can
// pollute Object.prototype for the entire process.
app.post('/api/profile', (req, res) => {
  const profile = _.merge({}, defaultProfile, req.body)
  res.json({ profile })
})

// A freshly-created empty object has no reason to be an admin — unless
// Object.prototype itself has been polluted.
app.get('/api/flag', (req, res) => {
  const requester = {}
  if (requester.isAdmin) {
    res.json({ flag: FLAG })
    return
  }
  res.status(403).json({ error: 'admin only' })
})

app.listen(PORT, () => {
  console.log(`a06-vulnerable-components listening on :${PORT}`)
})
