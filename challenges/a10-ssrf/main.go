// Challenge a10-ssrf — OWASP A10: Server-Side Request Forgery.
//
// ⚠️ INTENTIONALLY VULNERABLE. /fetch fetches any URL the caller supplies,
// server-side, with no allowlist and no check against internal/loopback
// addresses — the classic SSRF primitive. This service also runs a second
// listener bound only to 127.0.0.1, standing in for a cloud metadata
// endpoint (like 169.254.169.254) that's only reachable from inside the
// host. This is a training target — never do this in real code. See
// README.md.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const flag = "CTF{a10_ssrf_t0_m3tadata}"

const pageHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WonderCorp Chat — #links</title>
<style>
  :root { --accent: #ec4899; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; height: 100vh; display: flex; flex-direction: column; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #3d0a26; color: #fbcfe8; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; gap: 10px; padding: 16px 32px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  .channel { color: var(--muted); font-weight: 400; font-size: 0.85em; }
  main { flex: 1; overflow-y: auto; max-width: 640px; margin: 0 auto; width: 100%; padding: 24px; }
  .story-msg { font-style: italic; color: var(--muted); font-size: 0.85em; margin-bottom: 20px; border-left: 2px solid var(--accent); padding-left: 10px; }
  .msg { margin-bottom: 16px; }
  .msg .bubble { display: inline-block; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 10px 14px; font-size: 0.9em; max-width: 90%; word-break: break-all; }
  .preview-card { margin-top: 6px; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; max-width: 90%; background: #0d0d12; }
  .preview-card .bar { background: #191924; padding: 6px 12px; font-size: 0.75em; color: var(--muted); display: flex; justify-content: space-between; }
  .preview-card .body { padding: 12px; font-size: 0.8em; font-family: ui-monospace, monospace; white-space: pre-wrap; word-break: break-all; max-height: 160px; overflow-y: auto; }
  .composer { border-top: 1px solid var(--border); padding: 16px 32px; }
  .composer-inner { max-width: 640px; margin: 0 auto; display: flex; gap: 10px; }
  input { flex: 1; padding: 12px 14px; border-radius: 10px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.9em; font-family: inherit; }
  button { padding: 12px 20px; border-radius: 10px; border: none; background: var(--accent); color: #2b0316; font-weight: 600; cursor: pointer; font-size: 0.9em; font-family: inherit; }
  button:hover { filter: brightness(1.1); }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A10: Server-Side Request Forgery) — not for production use</div>
  <header><span class="brand-icon">🌐</span> WonderCorp Chat <span class="channel">#links</span></header>

  <main id="messages">
    <p class="story-msg">Marketing wanted link previews like every other messaging app.
       Engineering delivered in an afternoon. Paste a link below — it's fetched
       server-side and unfurled right here.</p>
  </main>

  <div class="composer">
    <div class="composer-inner">
      <input id="urlInput" placeholder="Paste a link, e.g. https://example.com" autocomplete="off">
      <button id="sendBtn">Send</button>
    </div>
  </div>

<script>
const messages = document.getElementById('messages');
const urlInput = document.getElementById('urlInput');

async function send() {
  const url = urlInput.value.trim();
  if (!url) return;
  urlInput.value = '';

  const msg = document.createElement('div');
  msg.className = 'msg';
  msg.innerHTML = '<div class="bubble">' + url + '</div>';
  messages.appendChild(msg);

  const res = await fetch('/fetch?url=' + encodeURIComponent(url));
  const data = await res.json();

  const card = document.createElement('div');
  card.className = 'preview-card';
  card.innerHTML = res.ok
    ? '<div class="bar"><span>Link preview</span><span>HTTP ' + data.status + '</span></div><div class="body"></div>'
    : '<div class="bar"><span>Could not fetch link</span></div><div class="body"></div>';
  card.querySelector('.body').textContent = res.ok ? data.body : data.error;
  messages.appendChild(card);
  messages.scrollTop = messages.scrollHeight;
}

document.getElementById('sendBtn').addEventListener('click', send);
urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
</script>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

// BUG: fetches whatever URL the caller supplies with no allowlist and no
// check against internal/loopback/link-local addresses.
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, `{"error":"missing url query param"}`, http.StatusBadRequest)
		return
	}

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		http.Error(w, `{"error":"fetch failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"failed reading response"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": resp.StatusCode,
		"body":   string(body),
	})
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// internalSecretHandler models a cloud metadata endpoint (like the classic
// 169.254.169.254) that's only supposed to be reachable from inside the
// host — reachable here because it's bound to 127.0.0.1 and this process
// (and only this process) shares that loopback.
func internalSecretHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"flag": flag})
}

func main() {
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /", indexHandler)
	publicMux.HandleFunc("GET /fetch", fetchHandler)
	publicMux.HandleFunc("GET /healthz", healthzHandler)

	internalMux := http.NewServeMux()
	internalMux.HandleFunc("GET /internal/secret", internalSecretHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	internalPort := os.Getenv("INTERNAL_PORT")
	if internalPort == "" {
		internalPort = "8081"
	}

	go func() {
		log.Printf("a10-ssrf internal listener on 127.0.0.1:%s (loopback only)", internalPort)
		if err := http.ListenAndServe("127.0.0.1:"+internalPort, internalMux); err != nil {
			log.Fatal(err)
		}
	}()

	log.Printf("a10-ssrf listening on :%s", port)
	if err := http.ListenAndServe(":"+port, publicMux); err != nil {
		log.Fatal(err)
	}
}
