# Challenges

⚠️ **Every service in this directory is intentionally vulnerable.** Each maps to
one category of the [OWASP Top 10 (2021)](https://owasp.org/Top10/), runs in its
own container with its own in-memory/ephemeral data store, and is isolated at the
network layer (see `deploy/k8s/base/networkpolicies.yaml`) from the platform
database and from every other challenge. None of these services, patterns, or
dependency choices should ever be copied into production code.

## Conventions

- Each challenge exposes `GET /healthz` (200 OK) for container/k8s liveness probes.
- Each challenge exposes `GET /` with a short HTML page describing the scenario —
  players don't need the README to get started, but the README explains the
  intended exploit for anyone stuck or reviewing the material.
- The flag format is always `CTF{...}`. Flags are hardcoded per-challenge and
  match the seed data in `platform/cmd/seed/main.go` — that file is the single
  source of truth for flag values, points, and challenge metadata shown in the UI.
- State resets on container restart — challenges are meant to be replayed.

## Index

| Dir | OWASP category |
|---|---|
| `a01-broken-access-control` | A01: Broken Access Control |
| `a02-crypto-failures` | A02: Cryptographic Failures |
| `a03-injection` | A03: Injection |
| `a04-insecure-design` | A04: Insecure Design |
| `a05-security-misconfig` | A05: Security Misconfiguration |
| `a06-vulnerable-components` | A06: Vulnerable and Outdated Components |
| `a07-auth-failures` | A07: Identification and Authentication Failures |
| `a08-integrity-failures` | A08: Software and Data Integrity Failures |
| `a09-logging-failures` | A09: Security Logging and Monitoring Failures |
| `a10-ssrf` | A10: Server-Side Request Forgery |
