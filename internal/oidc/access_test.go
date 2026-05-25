package oidc

import (
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestMintAccessToken_RoundTripVerifies(t *testing.T) {
	c := require.New(t)

	kid, store := newSigningKey(t)
	_, priv, err := store.Active()
	c.NoError(err)

	now := time.Now().UTC().Truncate(time.Second)
	tok, err := MintAccessToken(AccessTokenInput{
		Issuer:    "http://op.local:8081",
		SubjectID: "sub-1",
		ClientID:  "demo-rp",
		IssuedAt:  now,
		Expiry:    now.Add(time.Hour),
		Scope:     []string{"openid", "profile"},
	}, priv, kid)
	c.NoError(err)

	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)

	c.Equal(kid, parsed.Headers[0].KeyID)
	c.Equal("at+jwt", parsed.Headers[0].ExtraHeaders[jose.HeaderType])

	var claims AccessTokenClaims
	c.NoError(parsed.Claims(&priv.PublicKey, &claims))
	c.Equal("http://op.local:8081", claims.Issuer)
	c.Equal("http://op.local:8081", claims.Audience, "access token audience is the issuer (this OP)")
	c.Equal("sub-1", claims.Subject)
	c.Equal("demo-rp", claims.ClientID)
	c.Equal("openid profile", claims.Scope)
	c.Equal(now.Unix(), claims.IssuedAt)
	c.Equal(now.Add(time.Hour).Unix(), claims.Expiry)
}
