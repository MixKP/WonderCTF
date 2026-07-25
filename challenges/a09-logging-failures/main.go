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
<head><title>A09: Logging Failures — Nobody's Watching</title>
<style>
  :root { --accent: #94a3b8; --accent-bg: #1e293b; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #12151b, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #12151b; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  fieldset { border: 1px solid #253044; border-radius: 10px; margin: 18px 0; padding: 14px 16px; background: rgba(255,255,255,0.02); }
  legend { padding: 0 8px; color: var(--accent); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
  input { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0b0e14; border: 1px solid #253044; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  button { padding: 10px 18px; background: var(--accent); color: #0b0e14; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 8px; }
  button:hover { filter: brightness(1.1); }
  pre { background: #0b0e14; border: 1px solid #253044; padding: 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
  #progress { color: #9ca3af; margin: 8px 0; }
</style>
</head>
<body>
  <span class="badge">👁️ OWASP A09</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Admin Console</h1>
  <p>Admin logs in with a 4-digit PIN — 10,000 possibilities, no rate limiting, no lockout.</p>

  <fieldset>
    <legend>1. Try a PIN</legend>
    <form id="loginForm">
      <input name="pin" placeholder="4-digit PIN" autocomplete="off" maxlength="4">
      <button type="submit">Log in</button>
    </form>
  </fieldset>

  <fieldset>
    <legend>2. Or just brute-force all 10,000</legend>
    <button id="bruteBtn" type="button">Try every PIN</button>
    <div id="progress"></div>
  </fieldset>

  <fieldset>
    <legend>3. Check what got logged</legend>
    <button id="auditBtn" type="button">GET /api/audit-log</button>
  </fieldset>

  <pre id="result">(nothing yet)</pre>

<script>
const result = document.getElementById('result');
const progress = document.getElementById('progress');

async function tryPin(pin) {
  const res = await fetch('/login', { method: 'POST', body: JSON.stringify({ pin }) });
  return { ok: res.ok, data: await res.json() };
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const { data } = await tryPin(fd.get('pin'));
  result.textContent = JSON.stringify(data, null, 2);
});

document.getElementById('bruteBtn').addEventListener('click', async () => {
  const btn = document.getElementById('bruteBtn');
  btn.disabled = true;
  const CONCURRENCY = 25;
  let next = 0;
  let found = null;

  async function worker() {
    while (next < 10000 && !found) {
      const pin = String(next++).padStart(4, '0');
      progress.textContent = 'trying ' + pin + ' ... (' + next + '/10000)';
      const { ok, data } = await tryPin(pin);
      if (ok) { found = { pin, data }; return; }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  btn.disabled = false;
  if (found) {
    progress.textContent = 'found it: ' + found.pin;
    result.textContent = JSON.stringify(found.data, null, 2);
  } else {
    progress.textContent = 'exhausted all 10,000 — something is wrong.';
  }
});

document.getElementById('auditBtn').addEventListener('click', async () => {
  const res = await fetch('/api/audit-log');
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
