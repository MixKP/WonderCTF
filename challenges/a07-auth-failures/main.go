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
	"html/template"
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
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A07: Auth Failures</div>
  <h1>Token-Based Dashboard</h1>
  <p>Demo login: <code>alice / alice123</code> — but alice isn't an admin.</p>
  <p><code>POST /login</code> with JSON <code>{"username","password"}</code> to get a token.</p>
  <p><code>GET /api/flag</code> with header <code>Authorization: Bearer &lt;token&gt;</code>.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
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
