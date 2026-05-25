package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // sql.Open("pgx", ...) for golang-migrate
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// testPool is set up once by TestMain and shared across every store test in
// the package. Each test resets the tables it touches via resetDB.
var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := tcpg.Run(ctx, "postgres:16-alpine",
		tcpg.WithDatabase("oidc"),
		tcpg.WithUsername("oidc"),
		tcpg.WithPassword("oidc"),
		tcpg.BasicWaitStrategies(),
	)
	if err != nil {
		log.Printf("skipping postgres store tests: cannot start container: %v", err)
		os.Exit(0)
	}

	defer func() {
		_ = container.Terminate(context.Background())
	}()

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("connection string: %v", err)
	}

	if err := runMigrations(dsn); err != nil {
		log.Fatalf("apply migrations: %v", err)
	}

	pool, err := NewPool(ctx, dsn)
	if err != nil {
		log.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	testPool = pool
	os.Exit(m.Run())
}

func runMigrations(dsn string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}

	// pgx's stdlib adapter gives us a *sql.DB on the same driver we use at
	// runtime, without pulling in lib/pq just for migrations.
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open sql db: %w", err)
	}
	defer sqlDB.Close()

	db, err := migratepg.WithInstance(sqlDB, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}

	mig, err := migrate.NewWithInstance("iofs", src, "postgres", db)
	if err != nil {
		return fmt.Errorf("migrate instance: %w", err)
	}

	if err := mig.Up(); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}

	return nil
}

func resetDB(t *testing.T, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stmt := "TRUNCATE "
	for i, tbl := range tables {
		if i > 0 {
			stmt += ", "
		}
		stmt += tbl
	}
	stmt += " RESTART IDENTITY CASCADE"

	if _, err := testPool.Exec(ctx, stmt); err != nil {
		t.Fatalf("reset db: %v", err)
	}
}
