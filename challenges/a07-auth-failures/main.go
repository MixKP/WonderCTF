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
<head><title>A07: Auth Failures — Trust Me, I'm a Token</title>
<style>
  :root { --accent: #6366f1; --accent-bg: #26265f; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #12122a, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #12122a; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  fieldset { border: 1px solid #23234a; border-radius: 10px; margin: 18px 0; padding: 14px 16px; background: rgba(255,255,255,0.02); }
  legend { padding: 0 8px; color: var(--accent); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
  input, textarea { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0d0d1f; border: 1px solid #23234a; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  textarea { height: 50px; }
  button { padding: 10px 18px; background: var(--accent); color: #0d0d24; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 8px; }
  button:hover { filter: brightness(1.1); }
  pre { background: #0d0d1f; border: 1px solid #23234a; padding: 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .story { font-style: italic; color: #cbd5e1; border-left: 2px solid var(--accent); padding-left: 12px; margin: 16px 0; opacity: 0.85; }
</style>
</head>
<body>
  <span class="badge">🪪 OWASP A07</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Token-Based Dashboard</h1>
  <p class="story">Phase one of WonderCorp's single sign-on rollout: "tokens everywhere,
     verify later." Phase two hasn't been scheduled.</p>
  <p>Demo login: <code>alice / alice123</code> — but alice isn't an admin. <code>GET /api/flag</code> is admin-only.</p>

  <fieldset>
    <legend>1. Log in as alice (get a legitimate token)</legend>
    <button id="loginBtn" type="button">Log in</button>
  </fieldset>

  <fieldset>
    <legend>2. Build a token by hand</legend>
    <p>Edit the header and payload JSON below, build the token, then send it.</p>
    <textarea id="header" spellcheck="false">{"alg":"HS256","typ":"JWT"}</textarea>
    <textarea id="payload" spellcheck="false">{"username":"alice","isAdmin":false}</textarea>
    <button id="buildBtn" type="button">Build token</button>
    <input id="token" placeholder="token appears here after building — or paste your own">
  </fieldset>

  <fieldset>
    <legend>3. Try it against /api/flag</legend>
    <button id="sendBtn" type="button">GET /api/flag</button>
  </fieldset>

  <pre id="result">(nothing yet)</pre>

<script>
const result = document.getElementById('result');
const tokenField = document.getElementById('token');

function b64url(obj) {
  const json = JSON.stringify(obj);
  return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

document.getElementById('loginBtn').addEventListener('click', async () => {
  const res = await fetch('/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'alice', password: 'alice123' }),
  });
  const data = await res.json();
  if (res.ok) tokenField.value = data.token;
  result.textContent = JSON.stringify(data, null, 2);
});

document.getElementById('buildBtn').addEventListener('click', () => {
  try {
    const header = JSON.parse(document.getElementById('header').value);
    const payload = JSON.parse(document.getElementById('payload').value);
    tokenField.value = b64url(header) + '.' + b64url(payload) + '.';
  } catch (err) {
    result.textContent = 'Invalid JSON: ' + err.message;
  }
});

document.getElementById('sendBtn').addEventListener('click', async () => {
  const res = await fetch('/api/flag', {
    headers: { Authorization: 'Bearer ' + tokenField.value },
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
