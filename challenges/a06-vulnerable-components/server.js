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
  fieldset { border: 1px solid #1f2a44; border-radius: 6px; margin: 16px 0; }
  legend { padding: 0 6px; color: #9ca3af; }
  textarea { display: block; margin: 8px 0; padding: 8px; width: 100%; box-sizing: border-box; background: #131a2b; border: 1px solid #1f2a44; color: #e5e7eb; font-family: monospace; height: 80px; }
  button { padding: 8px 16px; background: #0e7490; color: white; border: none; cursor: pointer; margin-right: 8px; }
  pre { background: #131a2b; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A06: Vulnerable and Outdated Components</div>
  <h1>Profile Service</h1>
  <p>This service ships an outdated, known-vulnerable dependency (see README for the CVE).
     Whatever JSON object you send here gets merged into a default profile server-side.</p>

  <fieldset>
    <legend>1. Update profile</legend>
    <form id="profileForm">
      <textarea name="body" spellcheck="false">{"theme":"light"}</textarea>
      <button type="submit">POST /api/profile</button>
    </form>
  </fieldset>

  <fieldset>
    <legend>2. Check flag (admin only)</legend>
    <button id="checkFlag" type="button">GET /api/flag</button>
  </fieldset>

  <pre id="result">(nothing yet)</pre>

<script>
const result = document.getElementById('result');

document.getElementById('profileForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  let parsed;
  try {
    parsed = JSON.parse(fd.get('body'));
  } catch (err) {
    result.textContent = 'Invalid JSON: ' + err.message;
    return;
  }
  const res = await fetch('/api/profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(parsed),
  });
  result.textContent = JSON.stringify(await res.json(), null, 2);
});

document.getElementById('checkFlag').addEventListener('click', async () => {
  const res = await fetch('/api/flag');
  result.textContent = JSON.stringify(await res.json(), null, 2);
});
</script>
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
