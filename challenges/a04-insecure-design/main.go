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
<head><title>A04: Insecure Design — Reset, Predictably</title>
<style>
  :root { --accent: #3b82f6; --accent-bg: #1e3a5f; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #0f1729, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #0e1524; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  fieldset { border: 1px solid #1c2a42; border-radius: 10px; margin: 18px 0; padding: 14px 16px; background: rgba(255,255,255,0.02); }
  legend { padding: 0 8px; color: var(--accent); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
  input { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0a0f1c; border: 1px solid #1c2a42; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  button { padding: 10px 18px; background: var(--accent); color: #041228; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 8px; }
  button:hover { filter: brightness(1.1); }
  pre { background: #0a0f1c; border: 1px solid #1c2a42; padding: 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
  #clock { color: #9ca3af; font-size: 0.9em; }
</style>
</head>
<body>
  <span class="badge">📐 OWASP A04</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Password Reset</h1>
  <p>Take over the <code>admin</code> account without ever knowing the password.</p>
  <p id="clock">current time (unix): —</p>

  <fieldset>
    <legend>1. Request a reset</legend>
    <form id="forgotForm">
      <input name="username" placeholder="username" autocomplete="off" value="admin">
      <button type="submit">Request reset</button>
    </form>
  </fieldset>

  <fieldset>
    <legend>2. Complete the reset</legend>
    <form id="resetForm">
      <input name="username" placeholder="username" autocomplete="off" value="admin">
      <input name="token" placeholder="token" autocomplete="off">
      <input name="newPassword" placeholder="new password" autocomplete="off" value="hacked123">
      <button type="submit">Reset password</button>
    </form>
  </fieldset>

  <pre id="result">(nothing yet)</pre>

<script>
const clock = document.getElementById('clock');
setInterval(() => { clock.textContent = 'current time (unix): ' + Math.floor(Date.now() / 1000); }, 250);

const result = document.getElementById('result');

document.getElementById('forgotForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const res = await fetch('/api/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ username: fd.get('username') }),
  });
  result.textContent = JSON.stringify(await res.json(), null, 2);
});

document.getElementById('resetForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const res = await fetch('/api/reset-password', {
    method: 'POST',
    body: JSON.stringify({
      username: fd.get('username'),
      token: fd.get('token'),
      newPassword: fd.get('newPassword'),
    }),
  });
  result.textContent = JSON.stringify(await res.json(), null, 2);
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
