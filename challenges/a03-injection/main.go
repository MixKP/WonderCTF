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
<head><title>A03: Injection — Login, Creatively</title>
<style>
  :root { --accent: #22d3ee; --accent-bg: #083344; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #0d1a1e, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  input { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0a1518; border: 1px solid #163841; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  button { padding: 10px 18px; background: var(--accent); color: #04262e; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
  button:hover { filter: brightness(1.1); }
  .result { margin-top: 16px; padding: 12px; border-radius: 8px; }
  .ok { background: #052e2b; color: #6ee7b7; }
  .err { background: #2e0505; color: #fca5a5; }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
</style>
</head>
<body>
  <span class="badge">💉 OWASP A03</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Staff Login</h1>
  <p>This portal's login query is built by string concatenation. Find a way in.</p>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="username" autocomplete="off">
    <input type="text" name="password" placeholder="password" autocomplete="off">
    <button type="submit">Log in</button>
  </form>
  {{if .Message}}
  <div class="result {{if .Success}}ok{{else}}err{{end}}">{{.Message}}</div>
  {{end}}
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
