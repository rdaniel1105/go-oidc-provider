package oidc

import (
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type singleKeyResolver struct {
	kid string
	pub *ecdsa.PublicKey
}

func (r *singleKeyResolver) PublicKeyByKID(kid string) (*ecdsa.PublicKey, error) {
	if kid != r.kid {
		return nil, ErrUnknownKID
	}
	return r.pub, nil
}

func mintAccess(t *testing.T) (token, issuer, kid string, pub *ecdsa.PublicKey, now time.Time) {
	t.Helper()
	kid, store := newSigningKey(t)
	_, priv, err := store.Active()
	require.NoError(t, err)

	issuer = "http://op.local:8081"
	now = time.Now().UTC().Truncate(time.Second)

	tok, err := MintAccessToken(AccessTokenInput{
		Issuer:    issuer,
		SubjectID: "sub-1",
		ClientID:  "demo-rp",
		IssuedAt:  now,
		Expiry:    now.Add(time.Hour),
		Scope:     []string{"openid", "email", "profile"},
	}, priv, kid)
	require.NoError(t, err)

	return tok, issuer, kid, &priv.PublicKey, now
}

func TestVerifyAccessToken_HappyPath(t *testing.T) {
	c := require.New(t)
	tok, issuer, kid, pub, now := mintAccess(t)

	claims, err := VerifyAccessToken(tok, &singleKeyResolver{kid: kid, pub: pub}, issuer, now)
	c.NoError(err)
	c.Equal("sub-1", claims.Subject)
	c.Equal("demo-rp", claims.ClientID)
	c.Equal("openid email profile", claims.Scope)
}

func TestVerifyAccessToken_Expired(t *testing.T) {
	c := require.New(t)
	tok, issuer, kid, pub, now := mintAccess(t)

	_, err := VerifyAccessToken(tok, &singleKeyResolver{kid: kid, pub: pub}, issuer, now.Add(2*time.Hour))
	c.ErrorIs(err, ErrAccessTokenExpired)
}

func TestVerifyAccessToken_UnknownKID(t *testing.T) {
	c := require.New(t)
	tok, issuer, _, pub, now := mintAccess(t)

	_, err := VerifyAccessToken(tok, &singleKeyResolver{kid: "other-kid", pub: pub}, issuer, now)
	c.ErrorIs(err, ErrAccessTokenInvalid)
}

func TestVerifyAccessToken_IssuerMismatch(t *testing.T) {
	c := require.New(t)
	tok, _, kid, pub, now := mintAccess(t)

	_, err := VerifyAccessToken(tok, &singleKeyResolver{kid: kid, pub: pub}, "http://other.example.com", now)
	c.ErrorIs(err, ErrAccessTokenInvalid)
}

func TestVerifyAccessToken_Malformed(t *testing.T) {
	c := require.New(t)
	_, issuer, kid, pub, now := mintAccess(t)

	_, err := VerifyAccessToken("not.a.jwt", &singleKeyResolver{kid: kid, pub: pub}, issuer, now)
	c.True(errors.Is(err, ErrAccessTokenInvalid))
}

func TestScopeList(t *testing.T) {
	c := require.New(t)
	c.Nil(ScopeList(""))
	c.Equal([]string{"openid"}, ScopeList("openid"))
	c.Equal([]string{"openid", "email", "profile"}, ScopeList("openid email profile"))
	c.Equal([]string{"openid", "email"}, ScopeList("openid  email"))
}
