package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleOPUser() *domain.OPUser {
	phone := "+573001234567"
	return &domain.OPUser{
		Email:         "alice@example.com",
		DisplayName:   "Alice",
		PhoneE164:     &phone,
		PasskeyUserID: uuid.New(),
	}
}

func TestOPUserStore_Create(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	in := sampleOPUser()
	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.NotEqual(uuid.Nil, got.ID)
	c.Equal(in.Email, got.Email)
	c.Equal(in.DisplayName, got.DisplayName)
	c.NotNil(got.PhoneE164)
	c.Equal(*in.PhoneE164, *got.PhoneE164)
	c.Equal(in.PasskeyUserID, got.PasskeyUserID)
	c.NotZero(got.CreatedAt)
}

func TestOPUserStore_Create_WithoutPhone(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	in := sampleOPUser()
	in.PhoneE164 = nil
	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.Nil(got.PhoneE164)
}

func TestOPUserStore_Create_DuplicateEmail(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	_, err := store.Create(ctx, sampleOPUser())
	c.NoError(err)

	second := sampleOPUser()
	second.PasskeyUserID = uuid.New()
	phone := "+573009999999"
	second.PhoneE164 = &phone

	_, err = store.Create(ctx, second)
	c.ErrorIs(err, domain.ErrEmailTaken)
}

func TestOPUserStore_Create_DuplicatePhone(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	_, err := store.Create(ctx, sampleOPUser())
	c.NoError(err)

	second := sampleOPUser()
	second.Email = "bob@example.com"
	second.PasskeyUserID = uuid.New()

	_, err = store.Create(ctx, second)
	c.ErrorIs(err, domain.ErrPhoneTaken)
}

func TestOPUserStore_Create_NullPhonesDoNotCollide(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	first := sampleOPUser()
	first.PhoneE164 = nil
	_, err := store.Create(ctx, first)
	c.NoError(err)

	second := sampleOPUser()
	second.Email = "bob@example.com"
	second.PhoneE164 = nil
	second.PasskeyUserID = uuid.New()
	_, err = store.Create(ctx, second)
	c.NoError(err)
}

func TestOPUserStore_Create_DuplicatePasskeyUserID(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	first := sampleOPUser()
	_, err := store.Create(ctx, first)
	c.NoError(err)

	second := sampleOPUser()
	second.Email = "bob@example.com"
	phone := "+573009999999"
	second.PhoneE164 = &phone
	second.PasskeyUserID = first.PasskeyUserID

	_, err = store.Create(ctx, second)
	c.ErrorIs(err, domain.ErrPasskeyUserIDTaken)
}

func TestOPUserStore_GetByID_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	_, err := store.GetByID(ctx, uuid.New())
	c.ErrorIs(err, domain.ErrOPUserNotFound)
}

func TestOPUserStore_GetByEmail(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	created, err := store.Create(ctx, sampleOPUser())
	c.NoError(err)

	got, err := store.GetByEmail(ctx, created.Email)
	c.NoError(err)
	c.Equal(created.ID, got.ID)
}

func TestOPUserStore_GetByPasskeyUserID(t *testing.T) {
	c := require.New(t)
	resetDB(t, "op_users")

	store := NewOPUserStore(testPool)
	ctx := context.Background()

	created, err := store.Create(ctx, sampleOPUser())
	c.NoError(err)

	got, err := store.GetByPasskeyUserID(ctx, created.PasskeyUserID)
	c.NoError(err)
	c.Equal(created.ID, got.ID)
}
