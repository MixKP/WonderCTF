// Challenge a03-injection — OWASP A03: Injection.
//
// ⚠️ INTENTIONALLY VULNERABLE. The /login handler builds a SQL query by
// concatenating raw user input instead of using parameterized queries. This
// is a training target — never do this in real code. See README.md for the
// intended exploit.
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "modernc.org/sqlite"
)

const flag = "CTF{a03_sql1_1s_st1ll_h3r3}"

var db *sql.DB

const pageTemplate = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp Intranet — Staff Login</title>
<style>
  :root { --accent: #22d3ee; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); display: flex; flex-direction: column; }
  .disclosure { background: #063542; color: #a5f3fc; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  .wrap { flex: 1; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { width: 100%; max-width: 360px; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); text-align: center; }
  .logo { width: 48px; height: 48px; border-radius: 12px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.4em; margin: 0 auto 14px; }
  h1 { font-size: 1.2em; margin: 0 0 4px; color: #f8fafc; }
  .sub { color: var(--muted); font-size: 0.85em; margin-bottom: 20px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.82em; margin-bottom: 20px; text-align: left; border-left: 2px solid var(--accent); padding-left: 10px; }
  label { display: block; font-size: 0.8em; color: var(--muted); margin-bottom: 4px; margin-top: 12px; text-align: left; }
  input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.95em; font-family: inherit; }
  button { width: 100%; margin-top: 20px; padding: 10px 12px; border-radius: 8px; border: none; background: var(--accent); color: #04262e; font-weight: 600; cursor: pointer; font-size: 0.95em; font-family: inherit; }
  button:hover { filter: brightness(1.1); }
  .result { margin-top: 18px; padding: 10px 12px; border-radius: 8px; font-size: 0.85em; text-align: left; }
  .ok { background: #052e2b; color: #6ee7b7; }
  .err { background: #2e0505; color: #fca5a5; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A03: Injection) — not for production use</div>
  <div class="wrap">
    <div class="card">
      <div class="logo">💉</div>
      <h1>WonderCorp Intranet</h1>
      <div class="sub">Staff Portal</div>
      <p class="story">Thrown together over a long weekend by an intern with database
         access and a deadline. It's been live for two years.</p>
      <form method="POST" action="/login">
        <label>Username</label>
        <input type="text" name="username" autocomplete="off">
        <label>Password</label>
        <input type="password" name="password" autocomplete="off">
        <button type="submit">Log in</button>
      </form>
      {{if .Message}}
      <div class="result {{if .Success}}ok{{else}}err{{end}}">{{.Message}}</div>
      {{end}}
    </div>
  </div>
  <footer>WonderCorp Intranet · OWASP A03 training instance</footer>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageTemplate))

type pageData struct {
	Message string
	Success bool
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1) // shared in-memory sqlite needs a single connection

	schema := `CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		is_admin INTEGER NOT NULL DEFAULT 0
	)`
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("create schema: %v", err)
	}

	seed := `INSERT INTO users (username, password, is_admin) VALUES
		('alice', 'password123', 0),
		('admin', 'Tr0ub4dor&3-Zx9mQ', 1)`
	if _, err := db.Exec(seed); err != nil {
		log.Fatalf("seed data: %v", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, pageData{})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABLE: raw string concatenation into the SQL query. A username
	// like  admin' --  comments out the password check entirely.
	query := fmt.Sprintf(
		"SELECT username, is_admin FROM users WHERE username = '%s' AND password = '%s' LIMIT 1",
		username, password,
	)

	row := db.QueryRow(query)
	var loggedInAs string
	var isAdmin int
	if err := row.Scan(&loggedInAs, &isAdmin); err != nil {
		renderPage(w, pageData{Message: "Invalid credentials.", Success: false})
		return
	}

	if isAdmin == 1 {
		renderPage(w, pageData{Message: fmt.Sprintf("Welcome, %s. %s", loggedInAs, flag), Success: true})
		return
	}
	renderPage(w, pageData{Message: fmt.Sprintf("Welcome, %s. (not an admin — keep looking)", loggedInAs), Success: false})
}

func renderPage(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	initDB()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a03-injection listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
