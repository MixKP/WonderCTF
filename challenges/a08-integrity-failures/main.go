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
  fieldset { border: 1px solid #1f2a44; border-radius: 6px; margin: 16px 0; }
  legend { padding: 0 6px; color: #9ca3af; }
  input, textarea { display: block; margin: 8px 0; padding: 8px; width: 100%; box-sizing: border-box; background: #131a2b; border: 1px solid #1f2a44; color: #e5e7eb; font-family: monospace; }
  textarea { height: 50px; }
  button { padding: 8px 16px; background: #0e7490; color: white; border: none; cursor: pointer; margin-right: 8px; }
  pre { background: #131a2b; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .hint { color: #9ca3af; font-size: 0.9em; }
</style>
</head>
<body>
  <div class="banner">⚠️ Intentionally vulnerable training service — OWASP A08: Software and Data Integrity Failures</div>
  <h1>Session Restore</h1>
  <p>This app lets clients restore a "signed" session blob for fast reconnects — a base64 JSON
     payload plus a "checksum" that's meant to prove it came from the server.</p>

  <fieldset>
    <legend>1. Encode your session data</legend>
    <textarea id="data" spellcheck="false">{"role":"user"}</textarea>
    <button id="encodeBtn" type="button">Base64 encode</button>
    <input id="encoded" readonly placeholder="base64 appears here">
    <p class="hint" id="checksumHint">Compute the MD5 of that base64 string yourself (e.g. <code>md5 -s "&lt;value&gt;"</code> on macOS,
      <code>echo -n "&lt;value&gt;" | md5sum</code> on Linux, or any online MD5 tool) and paste it below.</p>
  </fieldset>

  <fieldset>
    <legend>2. Submit</legend>
    <input id="checksum" placeholder="checksum (md5 of the base64 value above)">
    <button id="submitBtn" type="button">POST /api/session/restore</button>
  </fieldset>

  <pre id="result">(nothing yet)</pre>

<script>
const result = document.getElementById('result');
const encodedField = document.getElementById('encoded');

document.getElementById('encodeBtn').addEventListener('click', () => {
  try {
    const parsed = JSON.parse(document.getElementById('data').value);
    encodedField.value = btoa(JSON.stringify(parsed));
  } catch (err) {
    result.textContent = 'Invalid JSON: ' + err.message;
  }
});

document.getElementById('submitBtn').addEventListener('click', async () => {
  const res = await fetch('/api/session/restore', {
    method: 'POST',
    body: JSON.stringify({
      data: encodedField.value,
      checksum: document.getElementById('checksum').value,
    }),
  });
  result.textContent = JSON.stringify(await res.json(), null, 2);
});
</script>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
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
