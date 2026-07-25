// Challenge a08-integrity-failures — OWASP A08: Software and Data
// Integrity Failures.
//
// ⚠️ INTENTIONALLY VULNERABLE. This service accepts a client-supplied
// "session" blob with a "checksum" it claims to verify — but the checksum
// is an unkeyed MD5 hash of the data, so it isn't an integrity check at
// all: anyone can compute a valid checksum for any payload they invent.
// This is a training target — never do this in real code. See README.md.
package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
)

const flag = "CTF{a08_1ns3cur3_d3s3r14l1z4t10n}"

type sessionPayload struct {
	Role string `json:"role"`
}

type restoreRequest struct {
	Data     string `json:"data"`     // base64-encoded JSON sessionPayload
	Checksum string `json:"checksum"` // meant to prove Data wasn't tampered with
}

const pageHTML = `<!doctype html>
<html>
<head><title>A08: Integrity Failures — Untrusted Payload</title>
<style>
  body { font-family: monospace; background: #0b0f19; color: #e5e7eb; max-width: 640px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #22d3ee; }
  code { background: #131a2b; padding: 2px 6px; border-radius: 3px; }
  .banner { background: #2e2405; color: #fde68a; padding: 8px 12px; margin-bottom: 20px; border-radius: 4px; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A08: Software and Data Integrity Failures</div>
  <h1>Session Restore</h1>
  <p>This app lets clients restore a "signed" session blob for fast reconnects.</p>
  <p><code>POST /api/session/restore</code> with JSON <code>{"data","checksum"}</code>,
     where <code>data</code> is base64 JSON like <code>{"role":"user"}</code> and
     <code>checksum</code> is meant to prove it came from us.</p>
</body>
</html>`

var tmpl = template.Must(template.New("page").Parse(pageHTML))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

// BUG: this "checksum" is an unkeyed hash of attacker-controlled data. It
// proves the data wasn't corrupted in transit — it proves nothing about who
// produced it. A real integrity check needs a secret the client doesn't have
// (an HMAC key or a digital signature), not just any hash function.
func computeChecksum(data string) string {
	sum := md5.Sum([]byte(data))
	return hex.EncodeToString(sum[:])
}

func restoreSessionHandler(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if computeChecksum(req.Data) != req.Checksum {
		http.Error(w, `{"error":"checksum mismatch — session data corrupted"}`, http.StatusBadRequest)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, `{"error":"invalid session data encoding"}`, http.StatusBadRequest)
		return
	}

	var session sessionPayload
	if err := json.Unmarshal(decoded, &session); err != nil {
		http.Error(w, `{"error":"invalid session data"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if session.Role == "admin" {
		json.NewEncoder(w).Encode(map[string]string{"message": "session restored as admin", "flag": flag})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "session restored as " + session.Role})
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler)
	mux.HandleFunc("POST /api/session/restore", restoreSessionHandler)
	mux.HandleFunc("GET /healthz", healthzHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("a08-integrity-failures listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
