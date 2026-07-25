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
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  input { display: block; margin: 8px 0; padding: 8px; width: 100%; box-sizing: border-box; background: #131a2b; border: 1px solid #1f2a44; color: #e5e7eb; }
  button { padding: 8px 16px; background: #0e7490; color: white; border: none; cursor: pointer; }
  .result { margin-top: 16px; padding: 12px; border-radius: 4px; }
  .ok { background: #052e2b; color: #6ee7b7; }
  .err { background: #2e0505; color: #fca5a5; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A03: Injection</div>
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
