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
<head><title>A10: SSRF — Fetch Anything</title>
<style>
  :root { --accent: #ec4899; --accent-bg: #500724; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #1a0f18, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #1a0f16; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  form { margin: 18px 0; }
  input { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #150c13; border: 1px solid #331226; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  button { padding: 10px 18px; background: var(--accent); color: #2b0316; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
  button:hover { filter: brightness(1.1); }
</style>
</head>
<body>
  <span class="badge">🌐 OWASP A10</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>URL Preview Tool</h1>
  <p>Paste a URL and this service will fetch it for you, server-side.</p>
  <p>This container also runs something on <code>127.0.0.1</code> that's never
  published outside the container — but this service runs inside it too.</p>

  <form action="/fetch" method="GET">
    <input name="url" placeholder="https://example.com" autocomplete="off">
    <button type="submit">Fetch</button>
  </form>
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
