// Challenge a02-crypto-failures — OWASP A02: Cryptographic Failures.
//
// ⚠️ INTENTIONALLY VULNERABLE. Passwords are hashed with unsalted MD5 (fast,
// crackable, and identical hashes for identical passwords) and a legacy
// debug endpoint leaks those hashes to anyone. This is a training target —
// never do this in real code. See README.md.
package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

const flag = "CTF{a02_md5_1s_n0t_h4sh1ng}"

type account struct {
	Username string
	Password string // plaintext, only ever used at seed time to compute the hash below
	FullName string
	Dept     string
}

var accounts = []account{
	{"alice", "sunshine1", "Alice Chen", "Fulfillment"},
	{"admin", "letmein", "WonderCorp Admin", "IT"}, // deliberately weak — a top-10 password on every wordlist
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func findAccount(username string) (account, bool) {
	for _, a := range accounts {
		if a.Username == username {
			return a, true
		}
	}
	return account{}, false
}

const pageHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp IT Support Console</title>
<style>
  :root { --accent: #a855f7; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #2a0e42; color: #d8b4fe; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; gap: 10px; padding: 16px 32px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  main { max-width: 640px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 28px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 0.85em; margin-bottom: 16px; }
  label { display: block; font-size: 0.8em; color: var(--muted); margin-bottom: 4px; margin-top: 12px; }
  input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.95em; font-family: inherit; }
  .btn { margin-top: 16px; padding: 10px 16px; border-radius: 8px; border: none; background: var(--accent); color: #1a0a24; font-weight: 600; cursor: pointer; font-size: 0.9em; font-family: inherit; }
  .btn:hover { filter: brightness(1.08); }
  code { background: #150f1c; padding: 2px 6px; border-radius: 3px; color: var(--accent); font-size: 0.9em; }
  .profile { display: none; margin-top: 20px; border: 1px solid var(--border); border-radius: 10px; padding: 16px; background: #0d0d12; }
  .profile .row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 0.9em; border-bottom: 1px solid #1a1a22; }
  .profile .row:last-child { border-bottom: none; }
  .profile .k { color: var(--muted); }
  .security-box { margin-top: 12px; padding: 10px; background: #17101f; border-radius: 8px; font-size: 0.8em; }
  .security-box .label { color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; font-size: 0.85em; margin-bottom: 4px; }
  .security-box code { word-break: break-all; }
  .error-msg { color: #fca5a5; font-size: 0.85em; margin-top: 10px; }
  .success-msg { color: #86efac; font-size: 0.85em; margin-top: 10px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.9em; margin: -4px 0 16px; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A02: Cryptographic Failures) — not for production use</div>
  <header><span class="brand-icon">🔑</span> WonderCorp IT Support Console</header>

  <main>
    <div class="card">
      <h2>Account Lookup</h2>
      <p class="story">IT swears this account system is "basically retired" — right up until
         someone remembers three teams still depend on it.</p>
      <form id="lookupForm">
        <label>Username</label>
        <input name="username" autocomplete="off" value="admin">
        <button class="btn" type="submit">Look up account</button>
      </form>
      <div class="profile" id="profile">
        <div class="row"><span class="k">Name</span><span id="pName"></span></div>
        <div class="row"><span class="k">Department</span><span id="pDept"></span></div>
        <div class="security-box">
          <div class="label">Legacy security record (support use only)</div>
          <code id="pHash"></code>
        </div>
      </div>
      <div class="error-msg" id="lookupError"></div>
    </div>

    <div class="card">
      <h2>Employee Sign-In</h2>
      <div class="sub">Crack the legacy hash above with CrackStation, hashcat, or john — it's unsalted MD5.</div>
      <form id="loginForm">
        <label>Username</label>
        <input name="username" autocomplete="off" value="admin">
        <label>Password</label>
        <input name="password" type="password" autocomplete="off">
        <button class="btn" type="submit">Sign in</button>
      </form>
      <div class="error-msg" id="loginError"></div>
      <div class="success-msg" id="loginSuccess"></div>
    </div>
  </main>

  <footer>WonderCorp IT — internal tooling · OWASP A02 training instance</footer>

<script>
document.getElementById('lookupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const errEl = document.getElementById('lookupError');
  const profileEl = document.getElementById('profile');
  errEl.textContent = '';
  profileEl.style.display = 'none';

  const res = await fetch('/api/users/' + encodeURIComponent(fd.get('username')) + '/lookup');
  const data = await res.json();
  if (!res.ok) { errEl.textContent = data.error; return; }

  document.getElementById('pName').textContent = data.fullName;
  document.getElementById('pDept').textContent = data.department;
  document.getElementById('pHash').textContent = data.password_md5;
  profileEl.style.display = 'block';
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const errEl = document.getElementById('loginError');
  const okEl = document.getElementById('loginSuccess');
  errEl.textContent = '';
  okEl.textContent = '';

  const res = await fetch('/login', {
    method: 'POST',
    body: JSON.stringify({ username: fd.get('username'), password: fd.get('password') }),
  });
  const data = await res.json();
  if (!res.ok) { errEl.textContent = data.error; return; }
  okEl.textContent = data.flag ? (data.message + ' — ' + data.flag) : data.message;
});
</script>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

// lookupHandler is the vulnerable endpoint: an unauthenticated "support"
// lookup that hands back the account's legacy MD5 password hash to anyone
// who asks for a username.
func lookupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	acc, ok := findAccount(username)
	if !ok {
		http.Error(w, `{"error":"account not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username":     acc.Username,
		"fullName":     acc.FullName,
		"department":   acc.Dept,
		"password_md5": md5Hex(acc.Password),
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	acc, ok := findAccount(req.Username)
	if !ok || md5Hex(req.Password) != md5Hex(acc.Password) {
		http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if acc.Username == "admin" {
		json.NewEncoder(w).Encode(map[string]string{"message": "welcome back, admin", "flag": flag})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "welcome, " + acc.Username})
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("GET /api/users/{username}/lookup", lookupHandler)
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a02-crypto-failures listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
