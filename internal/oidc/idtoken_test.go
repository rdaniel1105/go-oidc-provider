package oidc

import (
	"io"
	"log/slog"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func newSigningKey(t *testing.T) (kid string, store *KeyStore) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewKeyStore(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	kid, _, err = store.Active()
	require.NoError(t, err)
	return kid, store
}

func TestMintIDToken_RoundTripVerifies(t *testing.T) {
	c := require.New(t)

	kid, store := newSigningKey(t)
	_, priv, err := store.Active()
	c.NoError(err)

	now := time.Now().UTC().Truncate(time.Second)
	tok, err := MintIDToken(IDTokenInput{
		Issuer:    "http://op.local:8081",
		SubjectID: "00000000-0000-0000-0000-000000000001",
		Audience:  "demo-rp",
		IssuedAt:  now,
		Expiry:    now.Add(time.Hour),
		AuthTime:  now.Add(-time.Minute),
		Nonce:     "n-0S6_WzA2Mj",
		ACR:       "urn:passkey",
		AMR:       []string{"webauthn", "user"},
		Scope:     []string{"openid", "email", "profile"},
		Email:     "alice@example.com",
		Name:      "Alice",
	}, priv, kid)
	c.NoError(err)
	c.NotEmpty(tok)

	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)

	// Header carries the kid so RPs can pick the right public key.
	c.Len(parsed.Headers, 1)
	c.Equal(kid, parsed.Headers[0].KeyID)
	c.Equal(string(jose.ES256), parsed.Headers[0].Algorithm)

	var claims IDTokenClaims
	c.NoError(parsed.Claims(&priv.PublicKey, &claims))
	c.Equal("http://op.local:8081", claims.Issuer)
	c.Equal("00000000-0000-0000-0000-000000000001", claims.Subject)
	c.Equal("demo-rp", claims.Audience)
	c.Equal(now.Unix(), claims.IssuedAt)
	c.Equal(now.Add(time.Hour).Unix(), claims.Expiry)
	c.Equal("n-0S6_WzA2Mj", claims.Nonce)
	c.Equal("urn:passkey", claims.ACR)
	c.Equal([]string{"webauthn", "user"}, claims.AMR)
	c.Equal("alice@example.com", claims.Email)
	c.NotNil(claims.EmailVerified)
	c.True(*claims.EmailVerified)
	c.Equal("Alice", claims.Name)
}

func TestMintIDToken_OmitsEmailWithoutScope(t *testing.T) {
	c := require.New(t)

	kid, store := newSigningKey(t)
	_, priv, err := store.Active()
	c.NoError(err)

	now := time.Now().UTC().Truncate(time.Second)
	tok, err := MintIDToken(IDTokenInput{
		Issuer:    "http://op.local:8081",
		SubjectID: "sub-1",
		Audience:  "demo-rp",
		IssuedAt:  now,
		Expiry:    now.Add(time.Hour),
		AuthTime:  now,
		Scope:     []string{"openid"},
		Email:     "alice@example.com",
		Name:      "Alice",
	}, priv, kid)
	c.NoError(err)

	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)
	var claims IDTokenClaims
	c.NoError(parsed.Claims(&priv.PublicKey, &claims))
	c.Empty(claims.Email)
	c.Nil(claims.EmailVerified)
	c.Empty(claims.Name)
}

