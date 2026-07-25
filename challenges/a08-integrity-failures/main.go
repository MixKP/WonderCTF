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
<head>
<meta charset="utf-8">
<title>WonderCorp Quick Sync</title>
<style>
  :root { --accent: #14b8a6; --bg: #0a0a0f; --panel: #131318; --border: #22222b; --text: #e5e7eb; --muted: #9199a8; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); }
  .disclosure { background: #082e29; color: #5eead4; font-size: 0.8em; text-align: center; padding: 6px 12px; }
  header { display: flex; align-items: center; gap: 10px; padding: 16px 32px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 1.1em; }
  .brand-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 1.1em; }
  main { max-width: 560px; margin: 0 auto; padding: 40px 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }
  h2 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0 0 16px; }
  .story { font-style: italic; color: var(--muted); font-size: 0.85em; margin: -6px 0 16px; }
  .sub { color: var(--muted); font-size: 0.85em; margin-top: -8px; margin-bottom: 14px; }
  label { display: block; font-size: 0.8em; color: var(--muted); margin-bottom: 4px; margin-top: 12px; }
  input, textarea { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border); background: #0d0d12; color: var(--text); font-size: 0.9em; font-family: inherit; }
  textarea { font-family: ui-monospace, monospace; font-size: 0.85em; height: 50px; }
  input[readonly] { font-family: ui-monospace, monospace; font-size: 0.8em; color: var(--muted); }
  button { padding: 9px 16px; border-radius: 8px; border: none; background: var(--accent); color: #032420; font-weight: 600; cursor: pointer; font-size: 0.9em; font-family: inherit; margin-top: 12px; }
  button:hover { filter: brightness(1.1); }
  .code-box { margin-top: 14px; padding: 14px; background: #081512; border: 1px dashed #1a352f; border-radius: 10px; }
  .code-box .label { font-size: 0.75em; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 6px; }
  .code-box .value { font-family: ui-monospace, monospace; font-size: 0.8em; word-break: break-all; color: var(--accent); }
  .status-msg { margin-top: 14px; padding: 10px 12px; border-radius: 8px; font-size: 0.85em; }
  .ok { background: #052e2b; color: #6ee7b7; }
  .err { background: #2e0505; color: #fca5a5; }
  footer { text-align: center; color: var(--muted); font-size: 0.75em; padding: 24px; }
</style>
</head>
<body>
  <div class="disclosure">⚠️ Intentionally vulnerable training service (OWASP A08: Software and Data Integrity Failures) — not for production use</div>
  <header><span class="brand-icon">🧬</span> WonderCorp Quick Sync</header>

  <main>
    <div class="card">
      <h2>Export a sync code</h2>
      <p class="story">A "fast reconnect" feature so users don't have to log in twice on a
         new device. Someone on the team was very proud of the integrity check they added.</p>
      <label>Session data (JSON)</label>
      <textarea id="data" spellcheck="false">{"role":"user"}</textarea>
      <button id="encodeBtn" type="button">Generate sync code</button>
      <div class="code-box">
        <div class="label">Data</div>
        <div class="value" id="encoded">—</div>
      </div>
    </div>

    <div class="card">
      <h2>Import a sync code</h2>
      <div class="sub">Paste a data value and its checksum to restore a session on this device.</div>
      <label>Data</label>
      <input id="importData" placeholder="base64 session data">
      <label>Checksum</label>
      <input id="importChecksum" placeholder="checksum for that data">
      <button id="submitBtn" type="button">Sync this device</button>
      <div class="status-msg" id="statusMsg" style="display:none;"></div>
    </div>
  </main>

  <footer>WonderCorp Quick Sync · OWASP A08 training instance</footer>

<script>
document.getElementById('encodeBtn').addEventListener('click', () => {
  try {
    const parsed = JSON.parse(document.getElementById('data').value);
    const encoded = btoa(JSON.stringify(parsed));
    document.getElementById('encoded').textContent = encoded;
    document.getElementById('importData').value = encoded;
  } catch (err) {
    alert('Invalid JSON: ' + err.message);
  }
});

document.getElementById('submitBtn').addEventListener('click', async () => {
  const res = await fetch('/api/session/restore', {
    method: 'POST',
    body: JSON.stringify({
      data: document.getElementById('importData').value,
      checksum: document.getElementById('importChecksum').value,
    }),
  });
  const data = await res.json();
  const el = document.getElementById('statusMsg');
  el.style.display = 'block';
  el.className = 'status-msg ' + (res.ok ? 'ok' : 'err');
  el.textContent = res.ok ? (data.message + (data.flag ? ' — ' + data.flag : '')) : data.error;
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
