// Challenge a09-logging-failures — OWASP A09: Security Logging and
// Monitoring Failures.
//
// ⚠️ INTENTIONALLY VULNERABLE. The admin account uses a 4-digit PIN, and
// nothing about failed login attempts is ever logged, rate-limited, or
// locked out — so a brute force that would trip alarms anywhere else here
// runs silently to completion. This is a training target — never do this
// in real code. See README.md.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

const flag = "CTF{a09_n0_l0gs_n0_al3rts}"
const adminPIN = "7361" // 4 digits — 10,000 possibilities, no rate limiting, no logging

// BUG: every failed login attempt disappears without a trace — nothing is
// written here, and /api/audit-log always reports an empty log no matter how
// many attempts were made. Compare with the platform's real
// middleware.RequestLogging, which logs every request.

const pageHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp Admin Console</title>
<style>
  :root { --accent: #94a3b8; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #1e293b; color: #cbd5e1; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; gap: 10px; padding: 16px 32px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  main { max-width: 480px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 28px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); text-align: center; }
  h1 { font-size: 1.1em; margin: 0 0 4px; color: #f8fafc; }
  .story { font-style: italic; color: var(--muted); font-size: 0.82em; margin: 8px 0 20px; text-align: left; border-left: 2px solid var(--accent); padding-left: 10px; }
  .dots { display: flex; justify-content: center; gap: 14px; margin: 20px 0; }
  .dot { width: 16px; height: 16px; border-radius: 50%; border: 2px solid var(--border); }
  .dot.filled { background: var(--accent); border-color: var(--accent); }
  .keypad { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; max-width: 240px; margin: 0 auto; }
  .keypad button { padding: 16px 0; font-size: 1.1em; border-radius: 10px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); cursor: pointer; font-family: inherit; }
  .keypad button:hover { background: #191924; }
  .keypad button.wide { grid-column: span 1; font-size: 0.85em; color: var(--muted); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 16px; text-align: left; }
  .btn-secondary { padding: 9px 16px; border-radius: 8px; border: 1px solid var(--border); background: transparent; color: var(--text); cursor: pointer; font-size: 0.85em; font-family: inherit; }
  .btn-secondary:hover { background: #191924; }
  #progress { color: var(--muted); font-size: 0.8em; margin-top: 10px; text-align: left; }
  pre { background: #0d0d12; border: 1px solid var(--border); padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; font-size: 0.8em; text-align: left; margin-top: 12px; }
  .status-msg { margin-top: 14px; padding: 10px 12px; border-radius: 8px; font-size: 0.85em; text-align: left; }
  .ok { background: #052e2b; color: #6ee7b7; }
  .err { background: #2e0505; color: #fca5a5; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A09: Security Logging and Monitoring Failures) — not for production use</div>
  <header><span class="brand-icon">👁️</span> WonderCorp Admin Console</header>

  <main>
    <div class="card">
      <h1>Enter PIN</h1>
      <p class="story">The admin console got a PIN lock after a security review flagged it as
         "wide open." The review didn't say what a good PIN policy looks like.</p>
      <div class="dots" id="dots">
        <div class="dot"></div><div class="dot"></div><div class="dot"></div><div class="dot"></div>
      </div>
      <div class="keypad" id="keypad">
        <button data-k="1">1</button><button data-k="2">2</button><button data-k="3">3</button>
        <button data-k="4">4</button><button data-k="5">5</button><button data-k="6">6</button>
        <button data-k="7">7</button><button data-k="8">8</button><button data-k="9">9</button>
        <button class="wide" data-k="clear">Clear</button><button data-k="0">0</button><button class="wide" data-k="back">⌫</button>
      </div>
      <div class="status-msg" id="statusMsg" style="display:none;"></div>
    </div>

    <div class="card" style="text-align:left;">
      <h2>Automated attempt</h2>
      <button class="btn-secondary" id="bruteBtn" type="button">Try every PIN (0000–9999)</button>
      <div id="progress"></div>
    </div>

    <div class="card" style="text-align:left;">
      <h2>Security activity</h2>
      <button class="btn-secondary" id="auditBtn" type="button">View audit log</button>
      <pre id="result" style="display:none;"></pre>
    </div>
  </main>

  <footer>WonderCorp Admin Console · OWASP A09 training instance</footer>

<script>
let pin = '';
const dots = document.querySelectorAll('.dot');
const statusMsg = document.getElementById('statusMsg');
const progress = document.getElementById('progress');
const result = document.getElementById('result');

function renderDots() {
  dots.forEach((d, i) => d.classList.toggle('filled', i < pin.length));
}

async function tryPin(p) {
  const res = await fetch('/login', { method: 'POST', body: JSON.stringify({ pin: p }) });
  return { ok: res.ok, data: await res.json() };
}

async function submitPin() {
  const { ok, data } = await tryPin(pin);
  statusMsg.style.display = 'block';
  statusMsg.className = 'status-msg ' + (ok ? 'ok' : 'err');
  statusMsg.textContent = ok ? (data.message + (data.flag ? ' — ' + data.flag : '')) : data.error;
  pin = '';
  renderDots();
}

document.getElementById('keypad').addEventListener('click', (e) => {
  const k = e.target.dataset.k;
  if (!k) return;
  if (k === 'clear') { pin = ''; }
  else if (k === 'back') { pin = pin.slice(0, -1); }
  else if (pin.length < 4) { pin += k; }
  renderDots();
  if (pin.length === 4) submitPin();
});

document.getElementById('bruteBtn').addEventListener('click', async () => {
  const btn = document.getElementById('bruteBtn');
  btn.disabled = true;
  const CONCURRENCY = 25;
  let next = 0;
  let found = null;

  async function worker() {
    while (next < 10000 && !found) {
      const p = String(next++).padStart(4, '0');
      progress.textContent = 'trying ' + p + ' ... (' + next + '/10000)';
      const { ok, data } = await tryPin(p);
      if (ok) { found = { pin: p, data }; return; }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  btn.disabled = false;
  if (found) {
    progress.textContent = 'found it: ' + found.pin;
    statusMsg.style.display = 'block';
    statusMsg.className = 'status-msg ok';
    statusMsg.textContent = found.data.message + ' — ' + found.data.flag;
  } else {
    progress.textContent = 'exhausted all 10,000 — something is wrong.';
  }
});

document.getElementById('auditBtn').addEventListener('click', async () => {
  const res = await fetch('/api/audit-log');
  result.style.display = 'block';
  result.textContent = JSON.stringify(await res.json(), null, 2);
});
</script>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct{ Pin string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// No logging, no lockout, no rate limit on this path — brute-forceable
	// in a few thousand requests, and nothing will ever notice.
	if req.Pin != adminPIN {
		http.Error(w, `{"error":"invalid pin"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "welcome, admin", "flag": flag})
}

// auditLogHandler always returns an empty log, regardless of how many login
// attempts have actually happened — there is no audit trail to show.
func auditLogHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]string{})
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /api/audit-log", auditLogHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a09-logging-failures listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
