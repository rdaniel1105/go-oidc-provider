package redis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleCIBARequest() domain.CIBARequest {
	return domain.CIBARequest{
		ClientID:                "demo-rp",
		OPUserID:                uuid.New(),
		Scope:                   []string{"openid", "payment"},
		BindingMessage:          "Authorize $50 to Café Acme",
		ACRValues:               []string{"urn:passkey"},
		ClientNotificationToken: "rp-correlation-id-123",
	}
}

func TestCIBARequestStore_IssueAndGet(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	ctx := context.Background()

	in := sampleCIBARequest()
	authReqID, err := store.Issue(ctx, in, 10*time.Minute)
	c.NoError(err)
	c.NotEmpty(authReqID)

	got, err := store.Get(ctx, authReqID)
	c.NoError(err)
	c.Equal(domain.CIBAStatusPending, got.Status)
	c.Equal(in.ClientID, got.ClientID)
	c.Equal(in.OPUserID, got.OPUserID)
	c.Equal(in.Scope, got.Scope)
	c.Equal(in.BindingMessage, got.BindingMessage)
	c.Equal(in.ACRValues, got.ACRValues)
	c.Equal(in.ClientNotificationToken, got.ClientNotificationToken)
	c.NotZero(got.IssuedAt)
	c.Nil(got.ApprovedAt)
	c.Nil(got.DeniedAt)
}

func TestCIBARequestStore_Get_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	_, err := store.Get(context.Background(), uuid.NewString())
	c.ErrorIs(err, domain.ErrCIBARequestNotFound)
}

func TestCIBARequestStore_Approve(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	ctx := context.Background()

	authReqID, err := store.Issue(ctx, sampleCIBARequest(), 10*time.Minute)
	c.NoError(err)

	approvedAt := time.Now()
	c.NoError(store.Approve(ctx, authReqID, approvedAt))

	got, err := store.Get(ctx, authReqID)
	c.NoError(err)
	c.Equal(domain.CIBAStatusApproved, got.Status)
	c.NotNil(got.ApprovedAt)
	c.WithinDuration(approvedAt, *got.ApprovedAt, time.Second)
	c.Nil(got.DeniedAt)
}

func TestCIBARequestStore_Deny(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	ctx := context.Background()

	authReqID, err := store.Issue(ctx, sampleCIBARequest(), 10*time.Minute)
	c.NoError(err)

	deniedAt := time.Now()
	c.NoError(store.Deny(ctx, authReqID, deniedAt))

	got, err := store.Get(ctx, authReqID)
	c.NoError(err)
	c.Equal(domain.CIBAStatusDenied, got.Status)
	c.NotNil(got.DeniedAt)
	c.WithinDuration(deniedAt, *got.DeniedAt, time.Second)
	c.Nil(got.ApprovedAt)
}

func TestCIBARequestStore_Approve_AlreadyTerminal(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	ctx := context.Background()

	authReqID, err := store.Issue(ctx, sampleCIBARequest(), 10*time.Minute)
	c.NoError(err)

	c.NoError(store.Approve(ctx, authReqID, time.Now()))

	// Second approval and a switch to deny must both be rejected.
	c.ErrorIs(store.Approve(ctx, authReqID, time.Now()), domain.ErrCIBANotPending)
	c.ErrorIs(store.Deny(ctx, authReqID, time.Now()), domain.ErrCIBANotPending)
}

func TestCIBARequestStore_Approve_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	err := store.Approve(context.Background(), uuid.NewString(), time.Now())
	c.ErrorIs(err, domain.ErrCIBARequestNotFound)
}

func TestCIBARequestStore_Delete(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	ctx := context.Background()

	authReqID, err := store.Issue(ctx, sampleCIBARequest(), 10*time.Minute)
	c.NoError(err)

	c.NoError(store.Delete(ctx, authReqID))

	_, err = store.Get(ctx, authReqID)
	c.ErrorIs(err, domain.ErrCIBARequestNotFound)

	// Deleting an already-deleted key is a no-op.
	c.NoError(store.Delete(ctx, authReqID))
}

func TestCIBARequestStore_Issue_PreservesTTL(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewCIBARequestStore(testClient)
	ctx := context.Background()

	authReqID, err := store.Issue(ctx, sampleCIBARequest(), 10*time.Minute)
	c.NoError(err)

	c.NoError(store.Approve(ctx, authReqID, time.Now()))

	ttl, err := testClient.TTL(ctx, cibaRequestKeyPrefix+authReqID).Result()
	c.NoError(err)
	c.Greater(ttl, 8*time.Minute, "approval must preserve a TTL close to the original")
	c.LessOrEqual(ttl, 10*time.Minute)
}
