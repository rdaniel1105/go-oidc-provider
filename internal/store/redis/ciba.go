package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

const cibaRequestKeyPrefix = "ciba_request:"

// CIBARequestStore stores backchannel authentication requests keyed by
// auth_req_id. The store implements the lifecycle transitions
// (Approve, Deny) atomically with a WATCH/MULTI cycle so two concurrent
// browser approvals cannot both succeed.
type CIBARequestStore struct {
	client *redis.Client
}

// NewCIBARequestStore returns a CIBARequestStore backed by the given client.
// Per-request TTLs are passed at Issue time rather than stored in the type
// because CIBA's requested_expiry varies per call.
func NewCIBARequestStore(client *redis.Client) *CIBARequestStore {
	return &CIBARequestStore{client: client}
}

// Issue persists the request under a freshly generated auth_req_id with the
// given TTL and returns the id. Status is forced to Pending and IssuedAt is
// stamped on entry, ignoring whatever the caller set.
func (s *CIBARequestStore) Issue(ctx context.Context, req domain.CIBARequest, ttl time.Duration) (string, error) {
	req.Status = domain.CIBAStatusPending
	req.IssuedAt = time.Now().UTC()
	req.ApprovedAt = nil
	req.DeniedAt = nil

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal ciba request: %w", err)
	}

	authReqID := uuid.NewString()

	if err := s.client.Set(ctx, cibaRequestKeyPrefix+authReqID, body, ttl).Err(); err != nil {
		return "", fmt.Errorf("set ciba request: %w", err)
	}

	return authReqID, nil
}

// Get returns the request payload. Returns ErrCIBARequestNotFound if the
// auth_req_id has expired or was never issued.
func (s *CIBARequestStore) Get(ctx context.Context, authReqID string) (*domain.CIBARequest, error) {
	raw, err := s.client.Get(ctx, cibaRequestKeyPrefix+authReqID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrCIBARequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get ciba request: %w", err)
	}

	var out domain.CIBARequest
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal ciba request: %w", err)
	}

	return &out, nil
}

// Delete removes the CIBARequest with the given auth_req_id. Used by
// the token endpoint after a successful approved-state redemption so
// the same auth_req_id cannot mint a second token pair; subsequent
// polls then fall into the not-found path and return expired_token.
// Delete is idempotent: deleting a missing key is not an error.
func (s *CIBARequestStore) Delete(ctx context.Context, authReqID string) error {
	if err := s.client.Del(ctx, cibaRequestKeyPrefix+authReqID).Err(); err != nil {
		return fmt.Errorf("delete ciba request: %w", err)
	}
	return nil
}

// Approve transitions a pending request to approved and stamps ApprovedAt.
// Returns ErrCIBARequestNotFound if the auth_req_id is unknown or expired,
// ErrCIBANotPending if the request is already in a terminal state.
// The remaining TTL on the key is preserved.
func (s *CIBARequestStore) Approve(ctx context.Context, authReqID string, at time.Time) error {
	return s.transition(ctx, authReqID, func(req *domain.CIBARequest) {
		req.Status = domain.CIBAStatusApproved
		ts := at.UTC()
		req.ApprovedAt = &ts
	})
}

// Deny transitions a pending request to denied and stamps DeniedAt.
// Same not-found / not-pending semantics as Approve.
func (s *CIBARequestStore) Deny(ctx context.Context, authReqID string, at time.Time) error {
	return s.transition(ctx, authReqID, func(req *domain.CIBARequest) {
		req.Status = domain.CIBAStatusDenied
		ts := at.UTC()
		req.DeniedAt = &ts
	})
}

func (s *CIBARequestStore) transition(ctx context.Context, authReqID string, apply func(*domain.CIBARequest)) error {
	key := cibaRequestKeyPrefix + authReqID

	txf := func(tx *redis.Tx) error {
		raw, err := tx.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return domain.ErrCIBARequestNotFound
		}
		if err != nil {
			return fmt.Errorf("get ciba request: %w", err)
		}

		var req domain.CIBARequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return fmt.Errorf("unmarshal ciba request: %w", err)
		}

		if req.Status != domain.CIBAStatusPending {
			return domain.ErrCIBANotPending
		}

		ttl, err := tx.TTL(ctx, key).Result()
		if err != nil {
			return fmt.Errorf("ttl ciba request: %w", err)
		}

		apply(&req)

		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("marshal ciba request: %w", err)
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, body, ttl)
			return nil
		})
		return err
	}

	for {
		err := s.client.Watch(ctx, txf, key)
		if err == nil {
			return nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			// Concurrent writer touched the key — retry the transition.
			continue
		}
		return err
	}
}
