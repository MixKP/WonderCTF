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
<head>
<meta charset="utf-8">
<title>WonderCorp — Profile Settings</title>
<style>
  :root { --accent: #22c55e; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #0f2e17; color: #86efac; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; gap: 10px; padding: 16px 32px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  main { max-width: 560px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 16px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.85em; margin: -6px 0 16px; }
  .pref-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 0.9em; }
  .pref-row:last-child { border-bottom: none; }
  select { background: #0d0d12; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-family: inherit; }
  textarea { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0a140b; border: 1px solid #1c3320; border-radius: 6px; color: #e5e7eb; font-family: ui-monospace, monospace; font-size: 0.85em; height: 90px; }
  button { padding: 9px 16px; background: var(--accent); color: #042808; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 0.9em; font-family: inherit; }
  button:hover { filter: brightness(1.1); }
  .btn-secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
  pre { background: #0a140b; border: 1px solid #1c3320; padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; font-size: 0.8em; margin-top: 12px; }
  .admin-panel { text-align: center; padding: 20px; color: var(--muted); }
  .admin-panel .lock { font-size: 1.8em; margin-bottom: 8px; }
  .admin-panel.unlocked { color: #86efac; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A06: Vulnerable and Outdated Components) — not for production use</div>
  <header><span class="brand-icon">📦</span> WonderCorp Profile Settings</header>

  <main>
    <div class="card">
      <h2>Preferences</h2>
      <p class="story">The new profile microservice replaced three legacy ones in a single
         sprint. Whoever wrote it was clearly optimizing for velocity.</p>
      <div class="pref-row"><span>Theme</span><span>dark</span></div>
      <div class="pref-row"><span>Notifications</span><span>on</span></div>
    </div>

    <div class="card">
      <h2>Advanced — Developer Mode</h2>
      <p style="color:var(--muted); font-size:0.85em; margin-top:-8px;">Import a raw settings
        object. Whatever you send here gets merged into your profile server-side.</p>
      <form id="profileForm">
        <textarea name="body" spellcheck="false">{"theme":"light"}</textarea>
        <button type="submit">Apply settings</button>
      </form>
      <pre id="result" style="display:none;"></pre>
    </div>

    <div class="card">
      <h2>Admin Tools</h2>
      <div class="admin-panel" id="adminPanel">
        <div class="lock">🔒</div>
        <div>Requires administrator access</div>
        <button class="btn-secondary" id="checkFlag" type="button" style="margin-top:12px;">Check access</button>
      </div>
    </div>

    <div class="card">
      <h2>Changelog</h2>
      <p style="color:var(--muted); font-size:0.85em; margin:0;">v2.1.0 — Migrated to this
        profile microservice. Dependency audit deferred: <code>lodash</code> stayed pinned at
        <code>4.17.4</code> to avoid breaking the merge logic before launch — revisit next sprint.</p>
    </div>
  </main>

  <footer>WonderCorp Profile Settings · OWASP A06 training instance</footer>

<script>
const result = document.getElementById('result');

document.getElementById('profileForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  let parsed;
  try {
    parsed = JSON.parse(fd.get('body'));
  } catch (err) {
    result.style.display = 'block';
    result.textContent = 'Invalid JSON: ' + err.message;
    return;
  }
  const res = await fetch('/api/profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(parsed),
  });
  result.style.display = 'block';
  result.textContent = JSON.stringify(await res.json(), null, 2);
});

document.getElementById('checkFlag').addEventListener('click', async () => {
  const res = await fetch('/api/flag');
  const data = await res.json();
  const panel = document.getElementById('adminPanel');
  if (res.ok) {
    panel.classList.add('unlocked');
    panel.innerHTML = '<div class="lock">🔓</div><div>Access granted.</div><div style="margin-top:8px; font-family:ui-monospace,monospace;">' + data.flag + '</div>';
  } else {
    panel.querySelector('div:nth-child(2)').textContent = data.error;
  }
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
