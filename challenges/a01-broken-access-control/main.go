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
  fieldset { border: 1px solid #1f2a44; border-radius: 6px; margin: 16px 0; }
  legend { padding: 0 6px; color: #9ca3af; }
  input { display: block; margin: 8px 0; padding: 8px; width: 100%; box-sizing: border-box; background: #131a2b; border: 1px solid #1f2a44; color: #e5e7eb; }
  button { padding: 8px 16px; background: #0e7490; color: white; border: none; cursor: pointer; }
  #status { margin: 8px 0; color: #9ca3af; }
  pre { background: #131a2b; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A01: Broken Access Control</div>
  <h1>Order Lookup</h1>
  <p>Demo accounts: <code>alice / alice123</code>, <code>bob / bob123</code>. Orders are numbered 1001-1003 — you own exactly one of them.</p>

  <fieldset>
    <legend>1. Log in</legend>
    <form id="loginForm">
      <input name="username" placeholder="username" autocomplete="off" value="alice">
      <input name="password" placeholder="password" autocomplete="off" value="alice123">
      <button type="submit">Log in</button>
    </form>
    <div id="status">Not logged in.</div>
  </fieldset>

  <fieldset>
    <legend>2. View an order</legend>
    <form id="orderForm">
      <input name="id" placeholder="order id" autocomplete="off" value="1001">
      <button type="submit">View order</button>
    </form>
  </fieldset>

  <pre id="result">(nothing yet)</pre>

<script>
let token = null;
const status = document.getElementById('status');
const result = document.getElementById('result');

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const res = await fetch('/login', {
    method: 'POST',
    body: JSON.stringify({ username: fd.get('username'), password: fd.get('password') }),
  });
  const data = await res.json();
  if (res.ok) {
    token = data.token;
    status.textContent = 'Logged in as user #' + data.userId + '.';
  } else {
    token = null;
    status.textContent = 'Login failed: ' + data.error;
  }
});

document.getElementById('orderForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!token) { result.textContent = 'Log in first.'; return; }
  const fd = new FormData(e.target);
  const res = await fetch('/api/orders/' + encodeURIComponent(fd.get('id')), {
    headers: { Authorization: 'Bearer ' + token },
  });
  const data = await res.json();
  result.textContent = JSON.stringify(data, null, 2);
});
</script>
</body>
</html>`

func generateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("generate token: %v", err)
	}
	return hex.EncodeToString(b)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
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
