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
	"html/template"
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
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A04: Insecure Design</div>
  <h1>Password Reset</h1>
  <p><code>POST /api/forgot-password</code> with JSON <code>{"username"}</code> to request a reset.</p>
  <p><code>POST /api/reset-password</code> with JSON <code>{"username","token","newPassword"}</code> to complete it.</p>
  <p>Take over the <code>admin</code> account.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
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
