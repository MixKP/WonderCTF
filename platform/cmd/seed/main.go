// seed populates the platform DB with the challenge catalog and a demo admin
// account. It's idempotent (upserts) so `make seed` is safe to re-run.
//
// Flag values here are the single source of truth; each challenge under
// challenges/aXX-*/ hardcodes the matching flag in its own source — see that
// challenge's README for the intended exploit path.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/ctf-demo/platform/internal/auth"
	"github.com/ctf-demo/platform/internal/config"
	"github.com/ctf-demo/platform/internal/db"
)

type challengeSeed struct {
	id          string
	category    string
	title       string
	description string
	points      int
	url         string
	flag        string
}

var challenges = []challengeSeed{
	{
		id: "a01-broken-access-control", category: "A01: Broken Access Control",
		title:       "Somebody Else's Order",
		description: "The order lookup endpoint trusts whatever id you hand it. Find an order that isn't yours.",
		points:      200, url: "http://localhost:9001",
		flag: "CTF{a01_1d0r_ac7ually_ch3ck_own3rsh1p}",
	},
	{
		id: "a02-crypto-failures", category: "A02: Cryptographic Failures",
		title:       "Fast Hashes",
		description: "Passwords here are hashed the fast way. That's the bug.",
		points:      250, url: "http://localhost:9002",
		flag: "CTF{a02_md5_1s_n0t_h4sh1ng}",
	},
	{
		id: "a03-injection", category: "A03: Injection",
		title:       "Login, Creatively",
		description: "The login form builds its SQL query out of your input. Log in as admin without the password.",
		points:      150, url: "http://localhost:9003",
		flag: "CTF{a03_sql1_1s_st1ll_h3r3}",
	},
	{
		id: "a04-insecure-design", category: "A04: Insecure Design",
		title:       "Reset, Predictably",
		description: "Password reset tokens aren't random the way you'd hope. Take over the admin account.",
		points:      300, url: "http://localhost:9004",
		flag: "CTF{a04_pr3d1ctabl3_r3s3t_t0k3n}",
	},
	{
		id: "a05-security-misconfig", category: "A05: Security Misconfiguration",
		title:       "Left the Debug Door Open",
		description: "There's a debug surface exposed in this build that never should have shipped.",
		points:      100, url: "http://localhost:9005",
		flag: "CTF{a05_d3bug_m0d3_1n_pr0d}",
	},
	{
		id: "a06-vulnerable-components", category: "A06: Vulnerable and Outdated Components",
		title:       "Old Dependency, New Exploit",
		description: "This service ships a dependency with a known, public CVE. Exploit it.",
		points:      350, url: "http://localhost:9006",
		flag: "CTF{a06_kn0wn_cv3_1n_d3p}",
	},
	{
		id: "a07-auth-failures", category: "A07: Identification and Authentication Failures",
		title:       "Trust Me, I'm a Token",
		description: "This service's JWT verification is looser than it should be.",
		points:      300, url: "http://localhost:9007",
		flag: "CTF{a07_alg_n0n3_jwt_f0rg3ry}",
	},
	{
		id: "a08-integrity-failures", category: "A08: Software and Data Integrity Failures",
		title:       "Untrusted Payload",
		description: "This endpoint deserializes whatever you upload without checking it's what it claims to be.",
		points:      400, url: "http://localhost:9008",
		flag: "CTF{a08_1ns3cur3_d3s3r14l1z4t10n}",
	},
	{
		id: "a09-logging-failures", category: "A09: Security Logging and Monitoring Failures",
		title:       "Nobody's Watching",
		description: "Brute-force this login. Notice what doesn't happen.",
		points:      250, url: "http://localhost:9009",
		flag: "CTF{a09_n0_l0gs_n0_al3rts}",
	},
	{
		id: "a10-ssrf", category: "A10: Server-Side Request Forgery",
		title:       "Fetch Anything",
		description: "This service will fetch any URL you give it — including ones it shouldn't be able to reach.",
		points:      350, url: "http://localhost:9010",
		flag: "CTF{a10_ssrf_t0_m3tadata}",
	},
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migration failed", "err", err)
		os.Exit(1)
	}

	for _, ch := range challenges {
		flagHash, err := auth.HashPassword(ch.flag)
		if err != nil {
			slog.Error("hash flag failed", "challenge", ch.id, "err", err)
			os.Exit(1)
		}

		_, err = pool.Exec(ctx, `
			INSERT INTO challenges (id, category, title, description, points, url, flag_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				category = EXCLUDED.category,
				title = EXCLUDED.title,
				description = EXCLUDED.description,
				points = EXCLUDED.points,
				url = EXCLUDED.url,
				flag_hash = EXCLUDED.flag_hash`,
			ch.id, ch.category, ch.title, ch.description, ch.points, ch.url, flagHash)
		if err != nil {
			slog.Error("seed challenge failed", "challenge", ch.id, "err", err)
			os.Exit(1)
		}
		slog.Info("seeded challenge", "id", ch.id)
	}

	demoPasswordHash, err := auth.HashPassword("ChangeMe123!")
	if err != nil {
		slog.Error("hash demo password failed", "err", err)
		os.Exit(1)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO users (username, email, password_hash, is_admin)
		VALUES ('demo', 'demo@ctf.local', $1, false)
		ON CONFLICT (username) DO NOTHING`, demoPasswordHash)
	if err != nil {
		slog.Error("seed demo user failed", "err", err)
		os.Exit(1)
	}

	slog.Info("seed complete", "demo_user", "demo / ChangeMe123!")
}
