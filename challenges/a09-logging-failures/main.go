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
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
  fieldset { border: 1px solid #1f2a44; border-radius: 6px; margin: 16px 0; }
  legend { padding: 0 6px; color: #9ca3af; }
  input { display: block; margin: 8px 0; padding: 8px; width: 100%; box-sizing: border-box; background: #131a2b; border: 1px solid #1f2a44; color: #e5e7eb; }
  button { padding: 8px 16px; background: #0e7490; color: white; border: none; cursor: pointer; margin-right: 8px; }
  pre { background: #131a2b; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }
  #progress { color: #9ca3af; margin: 8px 0; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A09: Security Logging and Monitoring Failures</div>
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
