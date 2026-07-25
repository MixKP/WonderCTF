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
	"html/template"
	"log"
	"net/http"
	"os"
)

const flag = "CTF{a02_md5_1s_n0t_h4sh1ng}"

type account struct {
	Username string
	Password string // plaintext, only ever used at seed time to compute the hash below
}

var accounts = []account{
	{"alice", "sunshine1"},
	{"admin", "letmein"}, // deliberately weak — a top-10 password on every wordlist
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
<head><title>A02: Cryptographic Failures — Fast Hashes</title>
<style>
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A02: Cryptographic Failures</div>
  <h1>Legacy Account System</h1>
  <p>Passwords here are hashed with unsalted MD5. A legacy debug endpoint exposes those hashes.</p>
  <p><code>GET /api/users/{username}/hash</code> — leaks the stored MD5 hash.</p>
  <p><code>POST /login</code> with JSON <code>{"username","password"}</code>.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

func hashLeakHandler(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	acc, ok := findAccount(username)
	if !ok {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username":     acc.Username,
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
	mux.HandleFunc("GET /api/users/{username}/hash", hashLeakHandler)
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
