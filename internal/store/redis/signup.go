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

const signupStateKeyPrefix = "signup_state:"

// SignupStateStore persists the SignupState that bridges /users (begin)
// and /users/complete. Keys are namespaced by the passkey-side session_id
// the OP already threads through the ceremony, so no separate correlation
// id has to be exposed to the browser.
type SignupStateStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewSignupStateStore returns a SignupStateStore that writes keys with the
// given TTL. The TTL should bound how long a user has to complete the
// WebAuthn prompt; longer than the passkey service's challenge TTL is
// pointless because the underlying ceremony will already have expired.
func NewSignupStateStore(client *redis.Client, ttl time.Duration) *SignupStateStore {
	return &SignupStateStore{client: client, ttl: ttl}
}

// Save persists the state under the given session_id with the configured
// TTL. Overwrites any prior entry under the same session_id (which only
// happens if the same session_id is reused by a misbehaving client).
func (s *SignupStateStore) Save(ctx context.Context, sessionID string, state domain.SignupState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal signup state: %w", err)
	}

	if err := s.client.Set(ctx, signupStateKeyPrefix+sessionID, body, s.ttl).Err(); err != nil {
		return fmt.Errorf("set signup state: %w", err)
	}

	return nil
}

// Consume atomically reads and deletes the state for the given session_id.
// Returns ErrSignupStateNotFound if the entry is missing, expired, or
// already consumed. The single-use guarantee is enforced by GETDEL so a
// repeated POST /users/complete cannot create two op_user rows.
func (s *SignupStateStore) Consume(ctx context.Context, sessionID string) (domain.SignupState, error) {
	raw, err := s.client.GetDel(ctx, signupStateKeyPrefix+sessionID).Bytes()
	if errors.Is(err, redis.Nil) {
		return domain.SignupState{}, domain.ErrSignupStateNotFound
	}
	if err != nil {
		return domain.SignupState{}, fmt.Errorf("getdel signup state: %w", err)
	}

	var out domain.SignupState
	if err := json.Unmarshal(raw, &out); err != nil {
		return domain.SignupState{}, fmt.Errorf("unmarshal signup state: %w", err)
	}

	return out, nil
}
