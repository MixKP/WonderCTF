# OWASP Top 10 CTF Demo Platform

> ⚠️ **This repository is intentionally vulnerable.** The `challenges/` services
> each contain a deliberately planted security flaw for training purposes. Do
> **not** deploy any `challenges/*` service to a public network, use real
> credentials/data in it, or reuse its code in production systems. The
> `platform/` and `frontend/` apps that run the competition itself are written
> securely — the vulnerabilities live only inside the challenge containers.

A self-hosted Capture-The-Flag platform for teaching the
[OWASP Top 10 (2021)](https://owasp.org/Top10/). Players register, browse
challenges mapped 1:1 to each OWASP category, exploit the planted
vulnerability in an isolated container, and submit the recovered flag
(`CTF{...}`) to the platform for points on a live scoreboard.

## Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│  frontend    │────▶│   platform-api    │────▶│  postgres    │
│  Vue3+TS+TW  │      │  Go + Gin (secure)│      │  (platform)  │
└─────────────┘      └──────────────────┘      └─────────────┘
                             ▲  flag submission only
                             │  (no network path to challenges)
              ┌──────────────┴───────────────────────────┐
              │        challenges/  (10 isolated svcs)     │
              │  a01 … a10, one per OWASP Top 10 category  │
              │  each: own container, own flag, own README │
              └────────────────────────────────────────────┘
```

- **`platform/`** — Go + Gin + PostgreSQL. Auth (bcrypt + JWT), challenge
  catalog, flag submission (constant-time compare, rate-limited), scoreboard.
  This is the *secure* reference implementation.
- **`frontend/`** — Vue 3 + TypeScript + Tailwind CSS (Vite, Pinia, Vue Router).
- **`challenges/aXX-*/`** — ten standalone services, each with exactly one
  planted OWASP Top 10 vulnerability and a hardcoded flag. See each
  challenge's `README.md` for the category, the intended exploit, and the
  flag format.
- **`deploy/k8s/`** — kustomize manifests. `NetworkPolicy` objects ensure
  challenge pods cannot reach the platform database or each other.
- **Trivy** scans every built image (`make scan` locally, GitHub Actions in
  CI) for HIGH/CRITICAL CVEs and misconfigurations.

## OWASP Top 10 (2021) mapping

| ID  | Category | Challenge |
|-----|----------|-----------|
| A01 | Broken Access Control | `challenges/a01-broken-access-control` |
| A02 | Cryptographic Failures | `challenges/a02-crypto-failures` |
| A03 | Injection | `challenges/a03-injection` |
| A04 | Insecure Design | `challenges/a04-insecure-design` |
| A05 | Security Misconfiguration | `challenges/a05-security-misconfig` |
| A06 | Vulnerable and Outdated Components | `challenges/a06-vulnerable-components` |
| A07 | Identification and Authentication Failures | `challenges/a07-auth-failures` |
| A08 | Software and Data Integrity Failures | `challenges/a08-integrity-failures` |
| A09 | Security Logging and Monitoring Failures | `challenges/a09-logging-failures` |
| A10 | Server-Side Request Forgery (SSRF) | `challenges/a10-ssrf` |

## Quick start

```bash
cp .env.example .env
make up          # docker compose: db, platform-api, frontend, all 10 challenges
make seed         # seed platform DB with challenge catalog + demo admin
```

Frontend: http://localhost:5173 · Platform API: http://localhost:8080 ·
Each challenge is published on its own port — see `docker-compose.yml`.

```bash
make down         # tear down
make scan         # Trivy image + config scan of every built image
make k8s-up       # apply kustomize base + local overlay to current kube-context
```

## Development

- Platform: `cd platform && go test ./...`
- Frontend: `cd frontend && npm install && npm run dev`
- Each challenge: `cd challenges/aXX-* && docker build -t ctf/aXX .`
