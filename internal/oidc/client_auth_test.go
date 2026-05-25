package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

type fakeClients struct {
	byClientID map[string]*domain.Client
}

func (f *fakeClients) GetByClientID(_ context.Context, id string) (*domain.Client, error) {
	c, ok := f.byClientID[id]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	return c, nil
}

func bcryptHash(t *testing.T, secret string) *string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)
	s := string(h)
	return &s
}

func makeReq(t *testing.T, basicAuth string, form url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}
	require.NoError(t, req.ParseForm())
	return req
}

func basic(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func TestAuthenticateClient_Basic(t *testing.T) {
	c := require.New(t)

	hash := bcryptHash(t, "super-secret")
	clients := &fakeClients{byClientID: map[string]*domain.Client{
		"demo-rp": {
			ID:                      uuid.New(),
			ClientID:                "demo-rp",
			ClientSecretHash:        hash,
			TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
		},
	}}

	got, err := AuthenticateClient(context.Background(), makeReq(t, basic("demo-rp", "super-secret"), url.Values{}), clients)
	c.NoError(err)
	c.Equal("demo-rp", got.ClientID)
}

func TestAuthenticateClient_Basic_WrongSecret(t *testing.T) {
	c := require.New(t)

	hash := bcryptHash(t, "correct")
	clients := &fakeClients{byClientID: map[string]*domain.Client{
		"demo-rp": {
			ClientID:                "demo-rp",
			ClientSecretHash:        hash,
			TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
		},
	}}

	_, err := AuthenticateClient(context.Background(), makeReq(t, basic("demo-rp", "WRONG"), url.Values{}), clients)
	cae, ok := errors.AsType[*ErrClientAuth](err)
	c.True(ok)
	c.Equal(ClientAuthErrInvalidClient, cae.Code)
}

func TestAuthenticateClient_Basic_UnknownClient(t *testing.T) {
	c := require.New(t)

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}

	_, err := AuthenticateClient(context.Background(), makeReq(t, basic("ghost", "x"), url.Values{}), clients)
	cae, ok := errors.AsType[*ErrClientAuth](err)
	c.True(ok)
	c.Equal(ClientAuthErrInvalidClient, cae.Code)
}

func TestAuthenticateClient_BasicHeader_Malformed(t *testing.T) {
	c := require.New(t)

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}

	_, err := AuthenticateClient(context.Background(), makeReq(t, "Bearer foo", url.Values{}), clients)
	cae, ok := errors.AsType[*ErrClientAuth](err)
	c.True(ok)
	c.Equal(ClientAuthErrInvalidRequest, cae.Code)
}

func TestAuthenticateClient_BasicHeader_NotBase64(t *testing.T) {
	c := require.New(t)

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}

	_, err := AuthenticateClient(context.Background(), makeReq(t, "Basic !!!not-base64!!!", url.Values{}), clients)
	cae, ok := errors.AsType[*ErrClientAuth](err)
	c.True(ok)
	c.Equal(ClientAuthErrInvalidClient, cae.Code)
	c.NotEmpty(cae.WWWAuthenticate)
}

func TestAuthenticateClient_Post(t *testing.T) {
	c := require.New(t)

	hash := bcryptHash(t, "super-secret")
	clients := &fakeClients{byClientID: map[string]*domain.Client{
		"demo-rp": {
			ClientID:                "demo-rp",
			ClientSecretHash:        hash,
			TokenEndpointAuthMethod: domain.AuthMethodClientSecretPost,
		},
	}}

	form := url.Values{}
	form.Set("client_id", "demo-rp")
	form.Set("client_secret", "super-secret")

	got, err := AuthenticateClient(context.Background(), makeReq(t, "", form), clients)
	c.NoError(err)
	c.Equal("demo-rp", got.ClientID)
}

func TestAuthenticateClient_None(t *testing.T) {
	c := require.New(t)

	clients := &fakeClients{byClientID: map[string]*domain.Client{
		"public-spa": {
			ClientID:                "public-spa",
			ClientSecretHash:        nil,
			TokenEndpointAuthMethod: domain.AuthMethodNone,
		},
	}}

	form := url.Values{}
	form.Set("client_id", "public-spa")

	got, err := AuthenticateClient(context.Background(), makeReq(t, "", form), clients)
	c.NoError(err)
	c.Equal("public-spa", got.ClientID)
}

func TestAuthenticateClient_MethodMismatch(t *testing.T) {
	c := require.New(t)

	hash := bcryptHash(t, "x")
	clients := &fakeClients{byClientID: map[string]*domain.Client{
		"basic-client": {
			ClientID:                "basic-client",
			ClientSecretHash:        hash,
			TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
		},
	}}

	// Client is configured for Basic but presents Post — must be rejected.
	form := url.Values{}
	form.Set("client_id", "basic-client")
	form.Set("client_secret", "x")
	_, err := AuthenticateClient(context.Background(), makeReq(t, "", form), clients)
	cae, ok := errors.AsType[*ErrClientAuth](err)
	c.True(ok)
	c.Equal(ClientAuthErrInvalidClient, cae.Code)
}

func TestAuthenticateClient_MissingClientID(t *testing.T) {
	c := require.New(t)

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}

	_, err := AuthenticateClient(context.Background(), makeReq(t, "", url.Values{}), clients)
	cae, ok := errors.AsType[*ErrClientAuth](err)
	c.True(ok)
	c.Equal(ClientAuthErrInvalidClient, cae.Code)
}

func TestErrClientAuth_String(t *testing.T) {
	c := require.New(t)
	e := &ErrClientAuth{Code: ClientAuthErrInvalidClient, Description: "bad"}
	c.Contains(e.Error(), "invalid_client")
	c.Contains(e.Error(), "bad")

	bare := &ErrClientAuth{Code: ClientAuthErrInvalidRequest}
	c.Contains(bare.Error(), "invalid_request")
}
