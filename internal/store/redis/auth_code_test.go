package redis

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleAuthCode() domain.AuthCode {
	return domain.AuthCode{
		ClientID:            "demo-rp",
		OPUserID:            uuid.New(),
		RedirectURI:         "http://op.local:8082/callback",
		Scope:               []string{"openid", "profile"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
		ACR:                 "urn:passkey",
		AMR:                 []string{"webauthn", "user"},
		IssuedAt:            time.Now().UTC().Truncate(time.Second),
	}
}

func TestAuthCodeStore_IssueAndConsume(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewAuthCodeStore(testClient, 5*time.Minute)
	ctx := context.Background()

	in := sampleAuthCode()
	code, err := store.Issue(ctx, in)
	c.NoError(err)
	c.NotEmpty(code)

	got, err := store.Consume(ctx, code)
	c.NoError(err)
	c.Equal(in.ClientID, got.ClientID)
	c.Equal(in.OPUserID, got.OPUserID)
	c.Equal(in.RedirectURI, got.RedirectURI)
	c.Equal(in.Scope, got.Scope)
	c.Equal(in.CodeChallenge, got.CodeChallenge)
	c.Equal(in.Nonce, got.Nonce)
	c.Equal(in.ACR, got.ACR)
	c.Equal(in.AMR, got.AMR)
}

func TestAuthCodeStore_Consume_SingleUse(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewAuthCodeStore(testClient, 5*time.Minute)
	ctx := context.Background()

	code, err := store.Issue(ctx, sampleAuthCode())
	c.NoError(err)

	_, err = store.Consume(ctx, code)
	c.NoError(err)

	_, err = store.Consume(ctx, code)
	c.ErrorIs(err, domain.ErrAuthCodeNotFound)
}

func TestAuthCodeStore_Consume_Unknown(t *testing.T) {
	c := require.New(t)
	resetDB(t)

	store := NewAuthCodeStore(testClient, 5*time.Minute)
	_, err := store.Consume(context.Background(), "never-issued")
	c.ErrorIs(err, domain.ErrAuthCodeNotFound)
}
