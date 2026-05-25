package redis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func TestApprovalTokenStore_IssueAndConsume(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewApprovalTokenStore(testClient, 5*time.Minute)
	ctx := context.Background()
	authReqID := uuid.NewString()

	token, err := store.Issue(ctx, authReqID)
	c.NoError(err)
	c.NotEmpty(token)
	c.NotEqual(authReqID, token, "approval token must not leak the auth_req_id")

	got, err := store.Consume(ctx, token)
	c.NoError(err)
	c.Equal(authReqID, got)
}

func TestApprovalTokenStore_Consume_SingleUse(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewApprovalTokenStore(testClient, 5*time.Minute)
	ctx := context.Background()

	token, err := store.Issue(ctx, uuid.NewString())
	c.NoError(err)

	_, err = store.Consume(ctx, token)
	c.NoError(err)

	_, err = store.Consume(ctx, token)
	c.ErrorIs(err, domain.ErrApprovalTokenNotFound)
}

func TestApprovalTokenStore_Peek_DoesNotConsume(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewApprovalTokenStore(testClient, 5*time.Minute)
	ctx := context.Background()
	authReqID := uuid.NewString()

	token, err := store.Issue(ctx, authReqID)
	c.NoError(err)

	got, err := store.Peek(ctx, token)
	c.NoError(err)
	c.Equal(authReqID, got)

	// A second Peek still returns the same value — single-use is at Consume only.
	got, err = store.Peek(ctx, token)
	c.NoError(err)
	c.Equal(authReqID, got)

	// And Consume still works after Peek.
	got, err = store.Consume(ctx, token)
	c.NoError(err)
	c.Equal(authReqID, got)
}

func TestApprovalTokenStore_Peek_Unknown(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewApprovalTokenStore(testClient, 5*time.Minute)
	_, err := store.Peek(context.Background(), "never-issued")
	c.ErrorIs(err, domain.ErrApprovalTokenNotFound)
}

func TestApprovalTokenStore_Consume_Unknown(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewApprovalTokenStore(testClient, 5*time.Minute)
	_, err := store.Consume(context.Background(), "never-issued")
	c.ErrorIs(err, domain.ErrApprovalTokenNotFound)
}
