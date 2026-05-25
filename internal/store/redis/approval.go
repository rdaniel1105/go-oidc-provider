package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

const approvalTokenKeyPrefix = "approval_token:"

// ApprovalTokenStore maps URL-safe single-use tokens to the auth_req_id of
// the underlying CIBA request. The notifier (Telegram, WhatsApp, webhook,
// log) delivers a URL containing the token; visiting the URL is what binds
// the user-facing approval page back to the pending request.
type ApprovalTokenStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewApprovalTokenStore returns an ApprovalTokenStore that writes keys with
// the given TTL.
func NewApprovalTokenStore(client *redis.Client, ttl time.Duration) *ApprovalTokenStore {
	return &ApprovalTokenStore{client: client, ttl: ttl}
}

// Issue generates a URL-safe random token bound to authReqID and stores it
// with the configured TTL. The returned token is what the notifier embeds
// in the approval URL.
func (s *ApprovalTokenStore) Issue(ctx context.Context, authReqID string) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}

	if err := s.client.Set(ctx, approvalTokenKeyPrefix+token, authReqID, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("set approval token: %w", err)
	}

	return token, nil
}

// Consume atomically reads and deletes the approval token, returning the
// bound auth_req_id. Returns ErrApprovalTokenNotFound if the token is
// missing, expired, or already consumed.
func (s *ApprovalTokenStore) Consume(ctx context.Context, token string) (string, error) {
	raw, err := s.client.GetDel(ctx, approvalTokenKeyPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return "", domain.ErrApprovalTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getdel approval token: %w", err)
	}

	return raw, nil
}
