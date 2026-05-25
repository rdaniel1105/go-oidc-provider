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

const authSessionKeyPrefix = "auth_session:"

// AuthSessionStore holds the in-flight /oidc/authorize state under a fresh
// random session id. The id is what the login page submits at completion;
// the underlying request parameters never re-enter the URL, so the user
// cannot tamper with them by editing the address bar.
type AuthSessionStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewAuthSessionStore returns a store that writes keys with the given TTL.
func NewAuthSessionStore(client *redis.Client, ttl time.Duration) *AuthSessionStore {
	return &AuthSessionStore{client: client, ttl: ttl}
}

// Issue persists session under a freshly generated id and returns the id.
// The id is URL-safe and high-entropy; the login page embeds it as an
// opaque token.
func (s *AuthSessionStore) Issue(ctx context.Context, session domain.AuthSession) (string, error) {
	body, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("marshal auth session: %w", err)
	}

	id, err := newToken()
	if err != nil {
		return "", err
	}

	if err := s.client.Set(ctx, authSessionKeyPrefix+id, body, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("set auth session: %w", err)
	}

	return id, nil
}

// Consume atomically reads and deletes the auth session for the given id.
// Returns ErrAuthSessionNotFound if the entry is missing, expired, or
// already consumed. The single-use guarantee prevents the same successful
// login from minting two authorization codes.
func (s *AuthSessionStore) Consume(ctx context.Context, id string) (domain.AuthSession, error) {
	raw, err := s.client.GetDel(ctx, authSessionKeyPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return domain.AuthSession{}, domain.ErrAuthSessionNotFound
	}
	if err != nil {
		return domain.AuthSession{}, fmt.Errorf("getdel auth session: %w", err)
	}

	var out domain.AuthSession
	if err := json.Unmarshal(raw, &out); err != nil {
		return domain.AuthSession{}, fmt.Errorf("unmarshal auth session: %w", err)
	}

	return out, nil
}
