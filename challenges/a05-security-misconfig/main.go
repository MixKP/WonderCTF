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
  :root { --accent: #eab308; --accent-bg: #422006; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #1a1608, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #1a1608; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
</style>
</head>
<body>
  <span class="badge">⚙️ OWASP A05</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
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
