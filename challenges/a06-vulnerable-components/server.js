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
  :root { --accent: #22c55e; --accent-bg: #14320f; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #0f1a10, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #0e1810; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  fieldset { border: 1px solid #1c3320; border-radius: 10px; margin: 18px 0; padding: 14px 16px; background: rgba(255,255,255,0.02); }
  legend { padding: 0 8px; color: var(--accent); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
  textarea { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0a140b; border: 1px solid #1c3320; border-radius: 6px; color: #e5e7eb; font-family: inherit; height: 80px; }
  button { padding: 10px 18px; background: var(--accent); color: #042808; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 8px; }
  button:hover { filter: brightness(1.1); }
  pre { background: #0a140b; border: 1px solid #1c3320; padding: 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
  .story { font-style: italic; color: #cbd5e1; border-left: 2px solid var(--accent); padding-left: 12px; margin: 16px 0; opacity: 0.85; }
</style>
</head>
<body>
  <span class="badge">📦 OWASP A06</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Profile Service</h1>
  <p class="story">The new profile microservice replaced three legacy ones in a single
     sprint. Whoever wrote it was clearly optimizing for velocity.</p>
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
