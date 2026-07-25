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
<head>
<meta charset="utf-8">
<title>WonderCorp Ops Dashboard</title>
<style>
  :root { --accent: #eab308; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #3a2c05; color: #fde68a; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; justify-content: space-between; padding: 16px 32px; border-bottom: 1px solid var(--border); }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  nav { display: flex; gap: 20px; font-size: 0.85em; color: var(--muted); }
  nav a { color: var(--muted); text-decoration: none; }
  nav a:hover { color: var(--text); }
  main { max-width: 680px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 16px; }
  .status-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 0.9em; }
  .status-row:last-child { border-bottom: none; }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #4ade80; margin-right: 8px; }
  .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .stat { text-align: center; }
  .stat .n { font-size: 1.4em; font-weight: 700; color: #f8fafc; }
  .stat .l { font-size: 0.75em; color: var(--muted); margin-top: 2px; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A05: Security Misconfiguration) — not for production use</div>
  <header>
    <div class="brand"><span class="brand-icon">⚙️</span> WonderCorp Ops Dashboard</div>
    <nav><a href="#">Docs</a><a href="#">Support</a><a href="#">Status History</a></nav>
  </header>

  <main>
    <div class="card">
      <h2>Service Status</h2>
      <div class="status-row"><span><span class="status-dot"></span>API Gateway</span><span>Operational</span></div>
      <div class="status-row"><span><span class="status-dot"></span>Background Workers</span><span>Operational</span></div>
      <div class="status-row"><span><span class="status-dot"></span>Notifications</span><span>Operational</span></div>
    </div>

    <div class="card">
      <h2>At a Glance</h2>
      <div class="stat-grid">
        <div class="stat"><div class="n">342</div><div class="l">Days uptime</div></div>
        <div class="stat"><div class="n">7</div><div class="l">Active deploys</div></div>
        <div class="stat"><div class="n">v2.4.1</div><div class="l">Build version</div></div>
      </div>
    </div>

    <div class="card">
      <h2>About</h2>
      <p style="color:var(--muted); font-size:0.9em; margin:0;">A small internal tool nobody
        remembers building, let alone auditing. If it still works, why touch it?</p>
    </div>
  </main>

  <footer>WonderCorp Ops · internal tooling · OWASP A05 training instance</footer>
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
