// Challenge a05-security-misconfig — OWASP A05: Security Misconfiguration.
//
// ⚠️ INTENTIONALLY VULNERABLE. A debug/config endpoint that should only ever
// exist in development was left enabled and unauthenticated in this build,
// and it dumps the full internal configuration — including secrets. This is
// a training target — never do this in real code. See README.md.
package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
)

const flag = "CTF{a05_d3bug_m0d3_1n_pr0d}"

// internalConfig is what a real app might keep for its own diagnostics —
// never meant to leave the process. Shipping it behind an unauthenticated
// debug endpoint is the misconfiguration.
var internalConfig = map[string]any{
	"environment":          "production",
	"debug_mode":           true,
	"database_dsn":         "postgres://app:REDACTED@internal-db:5432/appdb",
	"internal_api_key":     "sk_live_51H8x...REDACTED",
	"feature_flags":        []string{"new_checkout", "beta_search"},
	"admin_bootstrap_flag": flag,
}

const pageHTML = `<!doctype html>
<html>
<head><title>A05: Security Misconfiguration — Left the Debug Door Open</title>
<style>
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A05: Security Misconfiguration</div>
  <h1>Internal App</h1>
  <p>This is a small internal tool. Nothing interesting here on the surface — but
  every build ships with its debug tooling intact, whether or not anyone remembered to disable it.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

// BUG: no authentication, and it should not exist in this build at all.
func debugConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(internalConfig)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("GET /debug/config", debugConfigHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a05-security-misconfig listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
