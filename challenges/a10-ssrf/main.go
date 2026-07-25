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
	"html/template"
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
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A10: Server-Side Request Forgery</div>
  <h1>URL Preview Tool</h1>
  <p>Paste a URL and this service will fetch it for you, server-side.</p>
  <p><code>GET /fetch?url=https://example.com</code></p>
  <p>This container also runs something on <code>127.0.0.1</code> that's never
  published outside the container — but this service runs inside it too.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
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
