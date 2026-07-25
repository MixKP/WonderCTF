// Challenge a01-broken-access-control — OWASP A01: Broken Access Control.
//
// ⚠️ INTENTIONALLY VULNERABLE. /api/orders/{id} checks that the caller is
// logged in, but never checks that the order belongs to them (IDOR). This is
// a training target — never do this in real code. See README.md.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

const flag = "CTF{a01_1d0r_ac7ually_ch3ck_own3rsh1p}"

type user struct {
	id       int
	username string
	password string
}

type order struct {
	ID      int    `json:"id"`
	OwnerID int    `json:"-"`
	Item    string `json:"item"`
	Notes   string `json:"notes"`
}

var users = []user{
	{1, "alice", "alice123"},
	{2, "bob", "bob123"},
	{3, "admin", "adminSecretPW!"},
}

var orders = map[int]order{
	1001: {ID: 1001, OwnerID: 1, Item: "Desk lamp", Notes: "Standard shipping, nothing special."},
	1002: {ID: 1002, OwnerID: 2, Item: "Mechanical keyboard", Notes: "Gift wrap requested."},
	1003: {ID: 1003, OwnerID: 3, Item: "Admin internal order", Notes: flag},
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]int{} // token -> userID
)

const pageHTML = `<!doctype html>
<html>
<head><title>A01: Broken Access Control — Somebody Else's Order</title>
<style>
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A01: Broken Access Control</div>
  <h1>Order Lookup</h1>
  <p>Demo accounts: <code>alice / alice123</code>, <code>bob / bob123</code>.</p>
  <p><code>POST /login</code> with JSON <code>{"username","password"}</code> to get a token.</p>
  <p><code>GET /api/orders/{id}</code> with header <code>Authorization: Bearer &lt;token&gt;</code> to view an order.</p>
  <p>Orders are numbered 1001-1003. You own one of them.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func generateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("generate token: %v", err)
	}
	return hex.EncodeToString(b)
}

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

	for _, u := range users {
		if u.username == req.Username && u.password == req.Password {
			token := generateToken()
			sessionsMu.Lock()
			sessions[token] = u.id
			sessionsMu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"token": token, "userId": u.id})
			return
		}
	}
	http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
}

// authenticate only checks that the token is valid — it deliberately does not
// tell the caller which order they're allowed to see. That check is missing
// from getOrderHandler, which is the actual bug.
func authenticate(r *http.Request) (userID int, ok bool) {
	header := r.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return 0, false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	id, found := sessions[parts[1]]
	return id, found
}

func getOrderHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := authenticate(r); !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, `{"error":"invalid order id"}`, http.StatusBadRequest)
		return
	}

	// BUG: no check that orders[id].OwnerID == the authenticated user's id.
	ord, found := orders[id]
	if !found {
		http.Error(w, `{"error":"order not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ord)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /api/orders/{id}", getOrderHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a01-broken-access-control listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
