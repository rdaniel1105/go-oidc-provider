package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleClient() *domain.Client {
	hash := "$2a$12$placeholderbcrypthashvaluexxxxxxxxxxxxxxxxxxxxxxx"
	return &domain.Client{
		ClientID:                hash[:8] + "-demo-rp",
		ClientSecretHash:        &hash,
		RedirectURIs:            []string{"http://op.local:8082/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}
}

func TestClientStore_Create(t *testing.T) {
	c := require.New(t)
	resetDB(t, "clients")

	store := NewClientStore(testPool)
	ctx := context.Background()

	in := sampleClient()
	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.NotEqual("00000000-0000-0000-0000-000000000000", got.ID.String())
	c.Equal(in.ClientID, got.ClientID)
	c.Equal(in.RedirectURIs, got.RedirectURIs)
	c.Equal(domain.AuthMethodClientSecretBasic, got.TokenEndpointAuthMethod)
	c.Nil(got.BackchannelTokenDeliveryMode)
	c.NotZero(got.CreatedAt)
	c.NotZero(got.UpdatedAt)
}

func TestClientStore_Create_DuplicateClientID(t *testing.T) {
	c := require.New(t)
	resetDB(t, "clients")

	store := NewClientStore(testPool)
	ctx := context.Background()

	in := sampleClient()
	_, err := store.Create(ctx, in)
	c.NoError(err)

	_, err = store.Create(ctx, in)
	c.ErrorIs(err, domain.ErrClientIDTaken)
}

func TestClientStore_Create_PersistsCIBAFields(t *testing.T) {
	c := require.New(t)
	resetDB(t, "clients")

	store := NewClientStore(testPool)
	ctx := context.Background()

	in := sampleClient()
	in.ClientID = "ciba-rp"
	in.GrantTypes = append(in.GrantTypes, "urn:openid:params:grant-type:ciba")
	endpoint := "https://rp.example.com/ciba/notify"
	in.ClientNotificationEndpoint = &endpoint
	mode := domain.CIBADeliveryPing
	in.BackchannelTokenDeliveryMode = &mode

	got, err := store.Create(ctx, in)
	c.NoError(err)
	c.Equal(&endpoint, got.ClientNotificationEndpoint)
	c.NotNil(got.BackchannelTokenDeliveryMode)
	c.Equal(domain.CIBADeliveryPing, *got.BackchannelTokenDeliveryMode)
}

func TestClientStore_GetByClientID(t *testing.T) {
	c := require.New(t)
	resetDB(t, "clients")

	store := NewClientStore(testPool)
	ctx := context.Background()

	in := sampleClient()
	created, err := store.Create(ctx, in)
	c.NoError(err)

	got, err := store.GetByClientID(ctx, in.ClientID)
	c.NoError(err)
	c.Equal(created.ID, got.ID)
	c.Equal(in.ClientID, got.ClientID)
}

func TestClientStore_GetByClientID_NotFound(t *testing.T) {
	c := require.New(t)
	resetDB(t, "clients")

	store := NewClientStore(testPool)
	ctx := context.Background()

	_, err := store.GetByClientID(ctx, "ghost")
	c.ErrorIs(err, domain.ErrClientNotFound)
}
