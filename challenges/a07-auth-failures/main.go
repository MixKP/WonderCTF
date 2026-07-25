// Challenge a07-auth-failures — OWASP A07: Identification and
// Authentication Failures.
//
// ⚠️ INTENTIONALLY VULNERABLE. This service hand-rolls JWT verification and
// trusts whatever algorithm the token's header claims, including "none" —
// meaning a token with an empty signature is accepted as valid. This is a
// training target — never do this in real code; use a maintained JWT
// library and pin the accepted algorithm (see platform/internal/auth/jwt.go
// for the correct approach). See README.md.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

const flag = "CTF{a07_alg_n0n3_jwt_f0rg3ry}"
const hmacSecret = "a07-signing-key-do-not-reuse"

type claims struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"isAdmin"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

var users = map[string]string{
	"alice": "alice123",
	// no admin credentials exist to log in with — admin access is only
	// reachable by forging a token, which is the point of this challenge.
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func issueToken(c claims) string {
	header := b64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(c)
	payload := b64url(payloadBytes)
	signingInput := header + "." + payload

	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(signingInput))
	sig := b64url(mac.Sum(nil))

	return signingInput + "." + sig
}

// verifyToken is the bug: it trusts the "alg" field in the attacker-supplied
// header instead of pinning to one algorithm server-side. A token with
// alg:"none" skips signature verification entirely.
func verifyToken(token string) (claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, false
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims{}, false
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return claims{}, false
	}

	switch hdr.Alg {
	case "HS256":
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		expected := b64url(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
			return claims{}, false
		}
	case "none":
		// BUG: no signature check at all for this branch.
	default:
		return claims{}, false
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, false
	}
	var c claims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return claims{}, false
	}
	return c, true
}

const pageHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp SSO</title>
<style>
  :root { --accent: #6366f1; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #201f42; color: #c7d2fe; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; justify-content: space-between; padding: 16px 32px; border-bottom: 1px solid var(--border); }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  .user-chip { display: none; align-items: center; gap: 10px; color: var(--muted); font-size: 0.9em; }
  .user-chip button { background: none; border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-family: inherit; }
  main { max-width: 560px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 28px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  .login-card { max-width: 360px; margin: 60px auto; }
  .login-card h1 { font-size: 1.3em; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 0.9em; margin-bottom: 20px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.85em; margin: -6px 0 16px; }
  label { display: block; font-size: 0.8em; color: var(--muted); margin-bottom: 4px; margin-top: 12px; }
  input, textarea { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.9em; font-family: inherit; }
  textarea { font-family: ui-monospace, monospace; font-size: 0.8em; height: 60px; }
  .btn { padding: 10px 16px; border-radius: 8px; border: none; background: var(--accent); color: #0d0d24; font-weight: 600; cursor: pointer; font-size: 0.9em; font-family: inherit; }
  .btn:hover { filter: brightness(1.1); }
  .btn-secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 16px; }
  .field-row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 0.9em; border-bottom: 1px solid var(--border); }
  .field-row:last-child { border-bottom: none; }
  .field-row .k { color: var(--muted); }
  .admin-panel { text-align: center; padding: 20px; color: var(--muted); }
  .admin-panel .lock { font-size: 1.8em; margin-bottom: 8px; }
  .admin-panel.unlocked { color: #86efac; }
  .error-msg { color: #fca5a5; font-size: 0.85em; margin-top: 10px; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A07: Auth Failures) — not for production use</div>
  <header>
    <div class="brand"><span class="brand-icon">🪪</span> WonderCorp SSO</div>
    <div class="user-chip" id="userChip">
      Signed in as <strong id="userLabel"></strong>
      <button id="logoutBtn">Log out</button>
    </div>
  </header>

  <main>
    <div id="loginView">
      <div class="card login-card">
        <h1>Sign in</h1>
        <div class="sub">WonderCorp single sign-on</div>
        <label>Username</label>
        <input id="loginUser" value="alice">
        <label>Password</label>
        <input id="loginPass" type="password" value="alice123">
        <button class="btn" id="loginBtn" style="width:100%; margin-top:20px;">Sign in</button>
        <div class="error-msg" id="loginError"></div>
      </div>
    </div>

    <div id="dashboardView" style="display:none;">
      <div class="card">
        <h2>Session</h2>
        <p class="story">Phase one of the SSO rollout: "tokens everywhere, verify later."
           Phase two hasn't been scheduled.</p>
        <div class="field-row"><span class="k">Username</span><span id="claimUser"></span></div>
        <div class="field-row"><span class="k">Admin</span><span id="claimAdmin"></span></div>
      </div>

      <div class="card">
        <h2>Token Inspector <span style="font-weight:400; text-transform:none; letter-spacing:0;">(dev tool)</span></h2>
        <p class="sub" style="margin-top:-8px;">"Rebuild token" re-encodes whatever's in both
           fields below with no signature — edit the header too, not just the payload.</p>
        <label>Header</label>
        <textarea id="header" spellcheck="false">{"alg":"HS256","typ":"JWT"}</textarea>
        <label>Payload</label>
        <textarea id="payload" spellcheck="false">{"username":"alice","isAdmin":false}</textarea>
        <button class="btn" id="buildBtn" style="margin-top:12px;">Rebuild token</button>
        <label>Current token</label>
        <input id="token" style="font-family:ui-monospace,monospace; font-size:0.75em;">
      </div>

      <div class="card">
        <h2>Admin Panel</h2>
        <div class="admin-panel" id="adminPanel">
          <div class="lock">🔒</div>
          <div>Requires administrator token</div>
          <button class="btn btn-secondary" id="checkBtn" style="margin-top:12px;">Check access</button>
        </div>
      </div>
    </div>
  </main>

  <footer>WonderCorp SSO · OWASP A07 training instance</footer>

<script>
let token = localStorage.getItem('a07_token');
let username = localStorage.getItem('a07_username');

function b64url(obj) {
  const json = JSON.stringify(obj);
  return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeClaims(t) {
  try {
    const payload = t.split('.')[1];
    const padded = payload.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(padded));
  } catch { return { username: '?', isAdmin: false }; }
}

function showDashboard() {
  document.getElementById('loginView').style.display = 'none';
  document.getElementById('dashboardView').style.display = 'block';
  document.getElementById('userChip').style.display = 'flex';
  document.getElementById('userLabel').textContent = username;
  document.getElementById('token').value = token;
  const claims = decodeClaims(token);
  document.getElementById('claimUser').textContent = claims.username;
  document.getElementById('claimAdmin').textContent = claims.isAdmin ? 'Yes' : 'No';
  document.getElementById('payload').value = JSON.stringify({ username: claims.username, isAdmin: claims.isAdmin });
}

document.getElementById('loginBtn').addEventListener('click', async () => {
  const res = await fetch('/login', {
    method: 'POST',
    body: JSON.stringify({
      username: document.getElementById('loginUser').value,
      password: document.getElementById('loginPass').value,
    }),
  });
  const data = await res.json();
  if (res.ok) {
    token = data.token;
    username = document.getElementById('loginUser').value;
    localStorage.setItem('a07_token', token);
    localStorage.setItem('a07_username', username);
    showDashboard();
  } else {
    document.getElementById('loginError').textContent = data.error;
  }
});

document.getElementById('logoutBtn').addEventListener('click', () => {
  token = null; username = null;
  localStorage.removeItem('a07_token'); localStorage.removeItem('a07_username');
  document.getElementById('loginView').style.display = 'block';
  document.getElementById('dashboardView').style.display = 'none';
  document.getElementById('userChip').style.display = 'none';
});

document.getElementById('buildBtn').addEventListener('click', () => {
  try {
    const header = JSON.parse(document.getElementById('header').value);
    const payload = JSON.parse(document.getElementById('payload').value);
    token = b64url(header) + '.' + b64url(payload) + '.';
    document.getElementById('token').value = token;
    const claims = decodeClaims(token);
    document.getElementById('claimUser').textContent = claims.username;
    document.getElementById('claimAdmin').textContent = claims.isAdmin ? 'Yes' : 'No';
  } catch (err) {
    alert('Invalid JSON: ' + err.message);
  }
});

document.getElementById('checkBtn').addEventListener('click', async () => {
  const t = document.getElementById('token').value;
  const res = await fetch('/api/flag', { headers: { Authorization: 'Bearer ' + t } });
  const data = await res.json();
  const panel = document.getElementById('adminPanel');
  if (res.ok) {
    panel.classList.add('unlocked');
    panel.innerHTML = '<div class="lock">🔓</div><div>Access granted.</div><div style="margin-top:8px; font-family:ui-monospace,monospace;">' + data.flag + '</div>';
  } else {
    panel.querySelector('div:nth-child(2)').textContent = data.error;
  }
});

if (token) showDashboard();
</script>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	pw, ok := users[req.Username]
	if !ok || pw != req.Password {
		http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	token := issueToken(claims{Username: req.Username, IsAdmin: false})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func flagHandler(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
		return
	}

	c, ok := verifyToken(parts[1])
	if !ok {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	if !c.IsAdmin {
		http.Error(w, `{"error":"admin only"}`, http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"flag": flag})
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /api/flag", flagHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a07-auth-failures listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
