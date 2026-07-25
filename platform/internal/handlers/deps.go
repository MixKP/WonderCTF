// Package handlers implements the platform's HTTP API.
package handlers

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctf-demo/platform/internal/auth"
)

type Deps struct {
	Pool   *pgxpool.Pool
	Tokens *auth.TokenIssuer
}
