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
	ID       int    `json:"id"`
	OwnerID  int    `json:"-"`
	Item     string `json:"item"`
	Customer string `json:"customer"`
	Status   string `json:"status"`
	Notes    string `json:"notes"`
}

var users = []user{
	{1, "alice", "alice123"},
	{2, "bob", "bob123"},
	{3, "admin", "adminSecretPW!"},
}

var orders = map[int]order{
	1001: {ID: 1001, OwnerID: 1, Item: "Desk lamp", Customer: "Alice Chen", Status: "Shipped", Notes: "Standard shipping, nothing special."},
	1002: {ID: 1002, OwnerID: 2, Item: "Mechanical keyboard", Customer: "Bob Martinez", Status: "Processing", Notes: "Gift wrap requested."},
	1003: {ID: 1003, OwnerID: 3, Item: "Admin internal order", Customer: "WonderCorp Admin", Status: "Delivered", Notes: flag},
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]int{} // token -> userID
)

const pageHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp Fulfillment — Order Tracker</title>
<style>
  :root { --accent: #f97316; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #3a1d05; color: #fdba74; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; justify-content: space-between; padding: 16px 32px; border-bottom: 1px solid var(--border); }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  .user-chip { display: none; align-items: center; gap: 10px; color: var(--muted); font-size: 0.9em; }
  .user-chip button { background: none; border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-family: inherit; }
  main { max-width: 720px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 28px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  .login-card { max-width: 360px; margin: 60px auto; }
  .login-card h1 { font-size: 1.3em; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 0.9em; margin-bottom: 20px; }
  label { display: block; font-size: 0.8em; color: var(--muted); margin-bottom: 4px; margin-top: 12px; }
  input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.95em; font-family: inherit; }
  .btn { width: 100%; margin-top: 20px; padding: 10px 12px; border-radius: 8px; border: none; background: var(--accent); color: #1a0d00; font-weight: 600; cursor: pointer; font-size: 0.95em; font-family: inherit; }
  .btn:hover { filter: brightness(1.08); }
  .demo-hint { margin-top: 16px; font-size: 0.8em; color: var(--muted); text-align: center; }
  code { background: #17120c; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 16px; }
  .order-row { display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid var(--border); }
  .order-row:last-child { border-bottom: none; }
  .order-id { font-family: ui-monospace, monospace; color: var(--muted); font-size: 0.85em; }
  .order-item { font-weight: 600; margin-left: 10px; }
  .badge-status { font-size: 0.75em; padding: 3px 10px; border-radius: 999px; font-weight: 600; white-space: nowrap; }
  .status-shipped { background: #1e3a5f; color: #93c5fd; }
  .status-processing { background: #3f2d05; color: #fcd34d; }
  .status-delivered { background: #14321f; color: #86efac; }
  .track-form { display: flex; gap: 8px; }
  .track-form input { flex: 1; }
  .track-form button { width: auto; margin-top: 0; padding: 10px 18px; white-space: nowrap; }
  #trackResult { margin-top: 16px; }
  .order-detail { border: 1px solid var(--border); border-radius: 10px; padding: 18px; background: #0d0d12; }
  .order-detail .field { display: flex; justify-content: space-between; padding: 6px 0; font-size: 0.9em; border-bottom: 1px solid #1a1a22; }
  .order-detail .field:last-child { border-bottom: none; }
  .order-detail .field .k { color: var(--muted); }
  .order-detail .notes { margin-top: 10px; padding: 10px; background: #171712; border-radius: 8px; font-size: 0.85em; color: #fcd34d; }
  .error-msg { color: #fca5a5; font-size: 0.85em; margin-top: 10px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.9em; margin: -8px 0 20px; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A01: Broken Access Control) — not for production use</div>
  <header>
    <div class="brand"><span class="brand-icon">📦</span> WonderCorp Fulfillment</div>
    <div class="user-chip" id="userChip">
      Signed in as <strong id="userLabel"></strong>
      <button id="logoutBtn">Log out</button>
    </div>
  </header>

  <main>
    <div id="loginView">
      <div class="card login-card">
        <h1>Sign in</h1>
        <div class="sub">Access your WonderCorp order history</div>
        <form id="loginForm">
          <label>Username</label>
          <input name="username" autocomplete="off" value="alice">
          <label>Password</label>
          <input name="password" type="password" autocomplete="off" value="alice123">
          <button class="btn" type="submit">Sign in</button>
        </form>
        <div class="error-msg" id="loginError"></div>
        <div class="demo-hint">Demo accounts: <code>alice / alice123</code>, <code>bob / bob123</code></div>
      </div>
    </div>

    <div id="dashboardView" style="display:none;">
      <div class="card">
        <h2>My Orders</h2>
        <div id="myOrders">Loading…</div>
      </div>

      <div class="card">
        <h2>Track an order</h2>
        <p class="story">"Just type in any order number and it'll pull it right up — way faster than
           the old system." — WonderCorp engineering, in the launch announcement.</p>
        <div class="track-form">
          <input id="trackInput" placeholder="Order number, e.g. 1001">
          <button class="btn" id="trackBtn">Track</button>
        </div>
        <div id="trackResult"></div>
      </div>
    </div>
  </main>

  <footer>WonderCorp Fulfillment — internal tooling · OWASP A01 training instance</footer>

<script>
let token = localStorage.getItem('a01_token');
let username = localStorage.getItem('a01_username');

function authHeaders() {
  return token ? { Authorization: 'Bearer ' + token } : {};
}

function statusBadge(status) {
  return '<span class="badge-status status-' + status.toLowerCase() + '">' + status + '</span>';
}

function renderOrderDetail(o) {
  return '<div class="order-detail">' +
    '<div class="field"><span class="k">Order</span><span>#' + o.id + '</span></div>' +
    '<div class="field"><span class="k">Item</span><span>' + o.item + '</span></div>' +
    '<div class="field"><span class="k">Customer</span><span>' + o.customer + '</span></div>' +
    '<div class="field"><span class="k">Status</span><span>' + statusBadge(o.status) + '</span></div>' +
    (o.notes ? '<div class="notes">📝 ' + o.notes + '</div>' : '') +
    '</div>';
}

function showDashboard() {
  document.getElementById('loginView').style.display = 'none';
  document.getElementById('dashboardView').style.display = 'block';
  document.getElementById('userChip').style.display = 'flex';
  document.getElementById('userLabel').textContent = username;
  loadMyOrders();
}

async function loadMyOrders() {
  const el = document.getElementById('myOrders');
  const res = await fetch('/api/orders/mine', { headers: authHeaders() });
  const data = await res.json();
  if (!res.ok) { el.textContent = data.error || 'Could not load orders.'; return; }
  if (data.length === 0) { el.textContent = 'No orders yet.'; return; }
  el.innerHTML = data.map(o =>
    '<div class="order-row">' +
      '<div><span class="order-id">#' + o.id + '</span><span class="order-item">' + o.item + '</span></div>' +
      statusBadge(o.status) +
    '</div>'
  ).join('');
}

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
    username = fd.get('username');
    localStorage.setItem('a01_token', token);
    localStorage.setItem('a01_username', username);
    document.getElementById('loginError').textContent = '';
    showDashboard();
  } else {
    document.getElementById('loginError').textContent = data.error;
  }
});

document.getElementById('logoutBtn').addEventListener('click', () => {
  token = null;
  username = null;
  localStorage.removeItem('a01_token');
  localStorage.removeItem('a01_username');
  document.getElementById('loginView').style.display = 'block';
  document.getElementById('dashboardView').style.display = 'none';
  document.getElementById('userChip').style.display = 'none';
  document.getElementById('trackResult').innerHTML = '';
});

document.getElementById('trackBtn').addEventListener('click', async () => {
  const id = document.getElementById('trackInput').value.trim();
  const result = document.getElementById('trackResult');
  if (!id) return;
  const res = await fetch('/api/orders/' + encodeURIComponent(id), { headers: authHeaders() });
  const data = await res.json();
  result.innerHTML = res.ok
    ? renderOrderDetail(data)
    : '<div class="error-msg">' + data.error + '</div>';
});

if (token) showDashboard();
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

// getOrderHandler is the vulnerable endpoint: any authenticated user can look
// up any order by id, regardless of who owns it.
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

// getMyOrdersHandler is the correctly-scoped counterpart: it only ever
// returns orders that belong to the authenticated user. Compare with
// getOrderHandler above — this is what an ownership check looks like.
func getMyOrdersHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := authenticate(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	mine := []order{}
	for _, ord := range orders {
		if ord.OwnerID == userID {
			mine = append(mine, ord)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mine)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /login", loginHandler)
	mux.HandleFunc("GET /api/orders/mine", getMyOrdersHandler)
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
