// Package postgres holds the pgx-backed stores for clients, op_users, and
// refresh_tokens, plus the embedded SQL migrations applied at startup and in
// integration tests.
package postgres

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationsFS exposes the embedded migration files so the server entrypoint
// and tests can drive golang-migrate from a single source of truth.
func MigrationsFS() embed.FS {
	return migrationsFS
}

// NewPool opens a pgx connection pool against the given URL and pings it to
// confirm the database is reachable before returning. Callers own the pool
// and are expected to Close it during shutdown.
func NewPool(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse pg config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pg pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return pool, nil
}
