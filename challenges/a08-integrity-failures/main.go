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
  :root { --accent: #14b8a6; --accent-bg: #0f3d38; }
  * { box-sizing: border-box; }
  body { font-family: 'Fira Code', ui-monospace, monospace; background: radial-gradient(circle at top, #0c1c1a, #05070d 65%); color: #e5e7eb; max-width: 680px; margin: 48px auto; padding: 0 20px; line-height: 1.5; }
  .badge { display: inline-block; font-size: 0.75em; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); border: 1px solid var(--accent); border-radius: 999px; padding: 4px 12px; margin-bottom: 12px; }
  h1 { color: #f8fafc; font-size: 1.6em; margin: 4px 0 6px; }
  code { background: #0c1917; padding: 2px 6px; border-radius: 3px; color: var(--accent); }
  .banner { background: var(--accent-bg); border-left: 3px solid var(--accent); color: #fde68a; padding: 10px 14px; margin-bottom: 20px; border-radius: 6px; font-size: 0.9em; }
  fieldset { border: 1px solid #1a352f; border-radius: 10px; margin: 18px 0; padding: 14px 16px; background: rgba(255,255,255,0.02); }
  legend { padding: 0 8px; color: var(--accent); font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; }
  input, textarea { display: block; margin: 8px 0; padding: 10px; width: 100%; background: #081512; border: 1px solid #1a352f; border-radius: 6px; color: #e5e7eb; font-family: inherit; }
  textarea { height: 50px; }
  button { padding: 10px 18px; background: var(--accent); color: #032420; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin-right: 8px; }
  button:hover { filter: brightness(1.1); }
  pre { background: #081512; border: 1px solid #1a352f; padding: 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .hint { color: #9ca3af; font-size: 0.9em; }
  .story { font-style: italic; color: #cbd5e1; border-left: 2px solid var(--accent); padding-left: 12px; margin: 16px 0; opacity: 0.85; }
</style>
</head>
<body>
  <span class="badge">🧬 OWASP A08</span>
  <div class="banner">⚠️ Intentionally vulnerable training service — not for production use</div>
  <h1>Session Restore</h1>
  <p class="story">A "fast reconnect" feature so users don't have to log in twice. Someone
     on the team was very proud of the integrity check they added.</p>
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
