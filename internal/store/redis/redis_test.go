package redis

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// testClient is set up once by TestMain and shared across all tests in the
// package. Each test flushes the db it touches via resetDB.
var testClient *redis.Client

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		log.Printf("skipping redis store tests: cannot start container: %v", err)
		os.Exit(0)
	}

	defer func() {
		_ = container.Terminate(context.Background())
	}()

	uri, err := container.ConnectionString(ctx)
	if err != nil {
		log.Fatalf("connection string: %v", err)
	}

	client, err := NewClient(ctx, uri)
	if err != nil {
		log.Fatalf("open redis client: %v", err)
	}
	defer func() { _ = client.Close() }()

	testClient = client
	os.Exit(m.Run())
}

func resetDB(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := testClient.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush redis: %v", err)
	}
}
