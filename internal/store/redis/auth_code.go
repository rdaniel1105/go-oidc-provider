package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

const authCodeKeyPrefix = "auth_code:"

// AuthCodeStore stores single-use authorization codes keyed by the opaque
// code string. Issuance generates a fresh URL-safe random token; consumption
// is an atomic GETDEL so a code can only be exchanged for tokens once.
type AuthCodeStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewAuthCodeStore returns an AuthCodeStore that writes keys with the given TTL.
func NewAuthCodeStore(client *redis.Client, ttl time.Duration) *AuthCodeStore {
	return &AuthCodeStore{client: client, ttl: ttl}
}

// Issue persists the given AuthCode payload under a freshly generated code
// and returns the code string. The code is the value handed back to the RP
// in the /authorize redirect; the caller must not store it elsewhere.
func (s *AuthCodeStore) Issue(ctx context.Context, code domain.AuthCode) (string, error) {
	body, err := json.Marshal(code)
	if err != nil {
		return "", fmt.Errorf("marshal auth code: %w", err)
	}

	token, err := newToken()
	if err != nil {
		return "", err
	}

	if err := s.client.Set(ctx, authCodeKeyPrefix+token, body, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("set auth code: %w", err)
	}

	return token, nil
}

// Consume atomically reads and deletes the authorization-code payload.
// Returns ErrAuthCodeNotFound if the code is missing, expired, or already
// consumed. The single-use guarantee is enforced by GETDEL.
func (s *AuthCodeStore) Consume(ctx context.Context, code string) (*domain.AuthCode, error) {
	raw, err := s.client.GetDel(ctx, authCodeKeyPrefix+code).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrAuthCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getdel auth code: %w", err)
	}

	var out domain.AuthCode
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal auth code: %w", err)
	}

	return &out, nil
}
