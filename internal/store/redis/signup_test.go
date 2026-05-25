package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleSignupState() domain.SignupState {
	phone := "+573001234567"
	return domain.SignupState{
		Email:       "alice@example.com",
		DisplayName: "Alice",
		PhoneE164:   &phone,
	}
}

func TestSignupStateStore_SaveAndConsume(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSignupStateStore(testClient, 5*time.Minute)
	ctx := context.Background()

	in := sampleSignupState()
	c.NoError(store.Save(ctx, "sess-1", in))

	got, err := store.Consume(ctx, "sess-1")
	c.NoError(err)
	c.Equal(in.Email, got.Email)
	c.Equal(in.DisplayName, got.DisplayName)
	c.NotNil(got.PhoneE164)
	c.Equal(*in.PhoneE164, *got.PhoneE164)
}

func TestSignupStateStore_Consume_SingleUse(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSignupStateStore(testClient, 5*time.Minute)
	ctx := context.Background()

	c.NoError(store.Save(ctx, "sess-1", sampleSignupState()))

	_, err := store.Consume(ctx, "sess-1")
	c.NoError(err)

	_, err = store.Consume(ctx, "sess-1")
	c.ErrorIs(err, domain.ErrSignupStateNotFound)
}

func TestSignupStateStore_Consume_Unknown(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSignupStateStore(testClient, 5*time.Minute)
	_, err := store.Consume(context.Background(), "never-saved")
	c.ErrorIs(err, domain.ErrSignupStateNotFound)
}

func TestSignupStateStore_Save_WithoutPhone(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewSignupStateStore(testClient, 5*time.Minute)
	ctx := context.Background()

	in := domain.SignupState{Email: "bob@example.com", DisplayName: "Bob"}
	c.NoError(store.Save(ctx, "sess-2", in))

	got, err := store.Consume(ctx, "sess-2")
	c.NoError(err)
	c.Nil(got.PhoneE164)
}
