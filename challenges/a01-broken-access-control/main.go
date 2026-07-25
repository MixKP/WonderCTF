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
  :root { --accent: #f97316; --accent-bg: #451a03; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #171310, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #17120c; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  fieldset { border: 1px solid #2a2116; border-radius: 10px; margin: 18px 0; padding: 14px 16px; background: rgba(255,255,255,0.02); }
  legend { padding: 0 8px; color: var(--accent); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
  input { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #0f0c08; border: 1px solid #2a2116; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  button { padding: 10px 18px; background: var(--accent); color: #1a0d00; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 8px; }
  button:hover { filter: brightness(1.1); }
  #status { margin: 8px 0; color: #9ca3af; }
  pre { background: #0f0c08; border: 1px solid #2a2116; padding: 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
  .story { font-style: italic; color: #cbd5e1; border-left: 2px solid var(--accent); padding-left: 12px; margin: 16px 0; opacity: 0.85; }
</style>
</head>
<body>
  <span class="badge">🔓 OWASP A01</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Order Lookup</h1>
  <p class="story">WonderCorp's fulfillment team just shipped a new order tracker so support
     reps can pull up any customer's order in seconds. It went out fast — maybe too fast.</p>
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
