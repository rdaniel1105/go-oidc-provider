// Package redis holds the go-redis-backed stores for the OP's short-lived
// state: authorization codes, CIBA requests, and approval tokens. Keys are
// namespaced by prefix and every write sets an explicit TTL so a leaked or
// forgotten record self-evicts.
package redis

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// NewClient parses the URL and pings Redis to confirm reachability before
// returning. The caller owns the client and must call Close on shutdown.
func NewClient(ctx context.Context, url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}

// newToken returns a 32-byte cryptographically random token, URL-safe-base64
// encoded without padding. Used for authorization codes and approval tokens.
func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
