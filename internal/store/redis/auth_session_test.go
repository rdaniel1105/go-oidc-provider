package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleAuthSession() domain.AuthSession {
	return domain.AuthSession{
		ClientID:            "demo-rp",
		RedirectURI:         "http://op.local:8082/callback",
		Scope:               []string{"openid", "profile"},
		State:               "rp-state-xyz",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
		ACRValues:           []string{"urn:passkey"},
	}
}

func TestAuthSessionStore_IssueAndConsume(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewAuthSessionStore(testClient, 5*time.Minute)
	ctx := context.Background()

	id, err := store.Issue(ctx, sampleAuthSession())
	c.NoError(err)
	c.NotEmpty(id)

	got, err := store.Consume(ctx, id)
	c.NoError(err)
	c.Equal("demo-rp", got.ClientID)
	c.Equal("http://op.local:8082/callback", got.RedirectURI)
	c.Equal([]string{"openid", "profile"}, got.Scope)
	c.Equal("rp-state-xyz", got.State)
	c.Equal("S256", got.CodeChallengeMethod)
}

func TestAuthSessionStore_Consume_SingleUse(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewAuthSessionStore(testClient, 5*time.Minute)
	ctx := context.Background()

	id, err := store.Issue(ctx, sampleAuthSession())
	c.NoError(err)

	_, err = store.Consume(ctx, id)
	c.NoError(err)

	_, err = store.Consume(ctx, id)
	c.ErrorIs(err, domain.ErrAuthSessionNotFound)
}

func TestAuthSessionStore_Consume_Unknown(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewAuthSessionStore(testClient, 5*time.Minute)
	_, err := store.Consume(context.Background(), "never-issued")
	c.ErrorIs(err, domain.ErrAuthSessionNotFound)
}
