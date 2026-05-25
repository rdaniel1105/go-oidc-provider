package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func createTestOPUser(t *testing.T, ctx context.Context) *domain.OPUser {
	t.Helper()

	users := NewOPUserStore(testPool)
	u, err := users.Create(ctx, &domain.OPUser{
		Email:         "rt-" + uuid.NewString() + "@example.com",
		DisplayName:   "RT User",
		PasskeyUserID: uuid.New(),
	})
	require.NoError(t, err)

	return u
}

func sampleRefreshToken(opUserID uuid.UUID, hash string) *domain.RefreshToken {
	return &domain.RefreshToken{
		TokenHash: hash,
		ClientID:  "demo-rp",
		OPUserID:  opUserID,
		Scope:     []string{"openid", "profile"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestRefreshTokenStore_Create(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	in := sampleRefreshToken(user.ID, "hash-1")
	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.NotEqual(uuid.Nil, got.ID)
	c.Equal(in.TokenHash, got.TokenHash)
	c.Equal(in.ClientID, got.ClientID)
	c.Equal(user.ID, got.OPUserID)
	c.Equal(in.Scope, got.Scope)
	c.NotZero(got.IssuedAt)
	c.WithinDuration(in.ExpiresAt, got.ExpiresAt, time.Second)
	c.Nil(got.RevokedAt)
	c.False(got.IsRevoked())
}

func TestRefreshTokenStore_Create_DuplicateHash(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	_, err := store.Create(ctx, sampleRefreshToken(user.ID, "dup"))
	c.NoError(err)

	_, err = store.Create(ctx, sampleRefreshToken(user.ID, "dup"))
	c.ErrorIs(err, domain.ErrRefreshTokenHashTaken)
}

func TestRefreshTokenStore_GetByHash(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	created, err := store.Create(ctx, sampleRefreshToken(user.ID, "lookup-me"))
	c.NoError(err)

	got, err := store.GetByHash(ctx, "lookup-me")
	c.NoError(err)
	c.Equal(created.ID, got.ID)
}

func TestRefreshTokenStore_GetByHash_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	store := NewRefreshTokenStore(testPool)
	_, err := store.GetByHash(context.Background(), "missing")
	c.ErrorIs(err, domain.ErrRefreshTokenNotFound)
}

func TestRefreshTokenStore_GetByHash_ReturnsRevokedRows(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	created, err := store.Create(ctx, sampleRefreshToken(user.ID, "to-revoke"))
	c.NoError(err)

	revokeAt := time.Now()
	c.NoError(store.Revoke(ctx, created.ID, revokeAt))

	got, err := store.GetByHash(ctx, "to-revoke")
	c.NoError(err, "rotation flow needs revoked rows to be returned, not hidden")
	c.True(got.IsRevoked())
	c.WithinDuration(revokeAt, *got.RevokedAt, time.Second)
}

func TestRefreshTokenStore_Revoke_AlreadyRevokedIsNoOp(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	created, err := store.Create(ctx, sampleRefreshToken(user.ID, "double-revoke"))
	c.NoError(err)

	first := time.Now()
	c.NoError(store.Revoke(ctx, created.ID, first))

	// A second revocation must not error and must not overwrite the
	// original revoked_at — the first revocation timestamp is the
	// authoritative moment of compromise.
	c.NoError(store.Revoke(ctx, created.ID, first.Add(time.Hour)))

	got, err := store.GetByHash(ctx, "double-revoke")
	c.NoError(err)
	c.WithinDuration(first, *got.RevokedAt, time.Second)
}

func TestRefreshTokenStore_Revoke_UnknownIDIsNotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	store := NewRefreshTokenStore(testPool)
	err := store.Revoke(context.Background(), uuid.New(), time.Now())
	c.ErrorIs(err, domain.ErrRefreshTokenNotFound)
}

func TestRefreshTokenStore_Create_GeneratesFamilyIDWhenZero(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	in := sampleRefreshToken(user.ID, "no-family")
	c.Equal(uuid.Nil, in.FamilyID)

	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.NotEqual(uuid.Nil, got.FamilyID, "store must allocate a family id for the first token in a chain")
}

func TestRefreshTokenStore_Create_PreservesExplicitFamilyID(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	family := uuid.New()
	in := sampleRefreshToken(user.ID, "explicit-family")
	in.FamilyID = family

	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.Equal(family, got.FamilyID, "rotation passes the parent's family id and the store must keep it")
}

func TestRefreshTokenStore_RevokeFamily(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	familyA := uuid.New()
	familyB := uuid.New()

	for _, h := range []string{"a1", "a2"} {
		in := sampleRefreshToken(user.ID, h)
		in.FamilyID = familyA
		_, err := store.Create(ctx, in)
		c.NoError(err)
	}
	in := sampleRefreshToken(user.ID, "b1")
	in.FamilyID = familyB
	_, err := store.Create(ctx, in)
	c.NoError(err)

	affected, err := store.RevokeFamily(ctx, familyA, time.Now())
	c.NoError(err)
	c.Equal(int64(2), affected)

	// Token from the untouched family is still live.
	got, err := store.GetByHash(ctx, "b1")
	c.NoError(err)
	c.Nil(got.RevokedAt)

	// Re-running is a no-op.
	affected, err = store.RevokeFamily(ctx, familyA, time.Now())
	c.NoError(err)
	c.Equal(int64(0), affected)
}

func TestRefreshTokenStore_RevokeAllForUser(t *testing.T) {
	c := require.New(t)
	resetDB(t, "refresh_tokens", "op_users")

	ctx := context.Background()
	user := createTestOPUser(t, ctx)
	other := createTestOPUser(t, ctx)
	store := NewRefreshTokenStore(testPool)

	_, err := store.Create(ctx, sampleRefreshToken(user.ID, "u-a"))
	c.NoError(err)
	_, err = store.Create(ctx, sampleRefreshToken(user.ID, "u-b"))
	c.NoError(err)
	_, err = store.Create(ctx, sampleRefreshToken(other.ID, "o-a"))
	c.NoError(err)

	affected, err := store.RevokeAllForUser(ctx, user.ID, time.Now())
	c.NoError(err)
	c.Equal(int64(2), affected)

	// Re-running yields zero — already-revoked rows are skipped.
	affected, err = store.RevokeAllForUser(ctx, user.ID, time.Now())
	c.NoError(err)
	c.Equal(int64(0), affected)

	// Other user's token is untouched.
	got, err := store.GetByHash(ctx, "o-a")
	c.NoError(err)
	c.Nil(got.RevokedAt)
}
