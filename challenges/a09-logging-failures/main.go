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
	"html/template"
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
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A09: Security Logging and Monitoring Failures</div>
  <h1>Admin Console</h1>
  <p>Admin logs in with a 4-digit PIN. <code>POST /login</code> with JSON <code>{"pin"}</code>.</p>
  <p>Check <code>GET /api/audit-log</code> before and after you try. Notice what doesn't change.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
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
