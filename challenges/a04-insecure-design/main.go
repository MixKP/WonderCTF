// Challenge a04-insecure-design — OWASP A04: Insecure Design.
//
// ⚠️ INTENTIONALLY VULNERABLE. Password reset "tokens" are just the current
// Unix timestamp — not a cryptographically random value — so anyone who
// knows roughly when a reset was requested can brute-force the token in a
// handful of guesses. No amount of careful coding fixes this; the design
// itself is the flaw. This is a training target — never do this in real
// code. See README.md.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const flag = "CTF{a04_pr3d1ctabl3_r3s3t_t0k3n}"

type account struct {
	Username string
	Password string
}

var (
	accountsMu sync.Mutex
	accounts   = map[string]*account{
		"alice": {"alice", "alice-original-pw"},
		"admin": {"admin", "admin-original-pw-nobody-knows"},
	}
)

const pageHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp Account Recovery</title>
<style>
  :root { --accent: #3b82f6; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #142748; color: #93c5fd; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; gap: 10px; padding: 16px 32px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  main { max-width: 420px; margin: 0 auto; padding: 60px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  h1 { font-size: 1.2em; margin: 0 0 4px; color: #f8fafc; }
  .sub { color: var(--muted); font-size: 0.85em; margin-bottom: 16px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.85em; margin-bottom: 20px; border-left: 2px solid var(--accent); padding-left: 10px; }
  label { display: block; font-size: 0.8em; color: var(--muted); margin-bottom: 4px; margin-top: 14px; }
  input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.95em; font-family: inherit; }
  input#code { text-align: center; letter-spacing: 0.15em; font-family: ui-monospace, monospace; font-size: 1.1em; }
  button { width: 100%; margin-top: 20px; padding: 10px 12px; border-radius: 8px; border: none; background: var(--accent); color: #041228; font-weight: 600; cursor: pointer; font-size: 0.95em; font-family: inherit; }
  button:hover { filter: brightness(1.1); }
  .sandbox-hint { margin-top: 16px; padding: 10px 12px; background: #0d0d12; border: 1px dashed var(--border); border-radius: 8px; font-size: 0.78em; color: var(--muted); }
  .sandbox-hint strong { color: var(--text); font-family: ui-monospace, monospace; }
  .step2 { display: none; }
  .status-msg { margin-top: 16px; padding: 10px 12px; border-radius: 8px; font-size: 0.85em; }
  .ok { background: #052e2b; color: #6ee7b7; }
  .err { background: #2e0505; color: #fca5a5; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A04: Insecure Design) — not for production use</div>
  <header><span class="brand-icon">📐</span> WonderCorp Account Recovery</header>

  <main>
    <div class="card">
      <div id="step1">
        <h1>Forgot your password?</h1>
        <div class="sub">Enter your username and we'll send you a reset code.</div>
        <p class="story">Support kept getting tickets for "I forgot my password," so someone
           built a self-serve flow. Ship first, ask questions later.</p>
        <form id="forgotForm">
          <label>Username</label>
          <input name="username" autocomplete="off" value="admin">
          <button type="submit">Send reset code</button>
        </form>
      </div>

      <div id="step2" class="step2">
        <h1>Enter your code</h1>
        <div class="sub" id="sentTo">We sent a reset code — check your inbox.</div>
        <div class="sandbox-hint">This sandbox doesn't actually send email — nothing will
          arrive in any inbox. Instead, here's the live value the reset code is generated
          from: <strong id="clock">—</strong></div>
        <form id="resetForm">
          <label>Reset code</label>
          <input id="code" name="token" autocomplete="off" placeholder="paste the number above">
          <label>New password</label>
          <input name="newPassword" autocomplete="off" value="hacked123">
          <button type="submit">Reset password</button>
        </form>
      </div>

      <div class="status-msg" id="statusMsg" style="display:none;"></div>
    </div>
  </main>

  <footer>WonderCorp Account Recovery · OWASP A04 training instance</footer>

<script>
let clockTimer = null;

function showStep2(username) {
  document.getElementById('step1').style.display = 'none';
  document.getElementById('step2').style.display = 'block';
  document.getElementById('sentTo').textContent = 'We sent a reset code for "' + username + '" — check your inbox.';
  const clock = document.getElementById('clock');
  clockTimer = setInterval(() => { clock.textContent = Math.floor(Date.now() / 1000); }, 250);
}

function showStatus(ok, text) {
  const el = document.getElementById('statusMsg');
  el.style.display = 'block';
  el.className = 'status-msg ' + (ok ? 'ok' : 'err');
  el.textContent = text;
}

document.getElementById('forgotForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const username = fd.get('username');
  const res = await fetch('/api/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ username }),
  });
  const data = await res.json();
  if (res.ok) {
    showStep2(username);
    document.getElementById('resetForm').dataset.username = username;
  } else {
    showStatus(false, data.error);
  }
});

document.getElementById('resetForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const username = e.target.dataset.username;
  const res = await fetch('/api/reset-password', {
    method: 'POST',
    body: JSON.stringify({
      username,
      token: fd.get('token'),
      newPassword: fd.get('newPassword'),
    }),
  });
  const data = await res.json();
  showStatus(res.ok, res.ok ? (data.status + (data.flag ? ' — ' + data.flag : '')) : data.error);
});
</script>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

// BUG: the "reset token" is just the current Unix timestamp as a string.
// It's not secret, not random, and trivially guessable within a few seconds
// of when the reset was requested.
func generateToken() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	accountsMu.Lock()
	_, exists := accounts[req.Username]
	accountsMu.Unlock()
	if !exists {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		return
	}

	// The token itself is intentionally never revealed here — that's the
	// point. The vulnerability is that it doesn't need to be: it's
	// predictable from the current time alone.
	_ = generateToken()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset instructions sent"})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Token, NewPassword string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Accept any token within a 30-second window of "now" — modeling an
	// attacker who triggered the reset a few seconds before guessing.
	now := time.Now().Unix()
	valid := false
	for delta := int64(-30); delta <= 30; delta++ {
		if req.Token == fmt.Sprintf("%d", now+delta) {
			valid = true
			break
		}
	}
	if !valid {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
		return
	}

	accountsMu.Lock()
	acc, exists := accounts[req.Username]
	if exists {
		acc.Password = req.NewPassword
	}
	accountsMu.Unlock()
	if !exists {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{"status": "password reset"}
	if req.Username == "admin" {
		resp["flag"] = flag
	}
	json.NewEncoder(w).Encode(resp)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /api/forgot-password", forgotPasswordHandler)
	mux.HandleFunc("POST /api/reset-password", resetPasswordHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a04-insecure-design listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
