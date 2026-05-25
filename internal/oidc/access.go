package oidc

import (
	"crypto/ecdsa"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// AccessTokenClaims is the JWT claim set this OP issues as the access
// token. The shape is intentionally narrow: only what userinfo and other
// resource servers need to authorize a request.
type AccessTokenClaims struct {
	// Issuer matches the OP's configured issuer URL.
	Issuer string `json:"iss"`
	// Subject is the op_user identifier.
	Subject string `json:"sub"`
	// Audience is the issuer itself — this OP's resource endpoints are
	// the access token's intended audience. Resource servers external
	// to the OP would need a separate token (a /token exchange or
	// /authorize with their own audience claim), out of scope for v1.
	Audience string `json:"aud"`
	// Expiry is the unix-seconds expiry time.
	Expiry int64 `json:"exp"`
	// IssuedAt is the unix-seconds issuance time.
	IssuedAt int64 `json:"iat"`
	// ClientID is the RP the token was issued to. Resource servers can
	// log it for audit; userinfo does not gate on it today.
	ClientID string `json:"client_id"`
	// Scope is the space-separated granted scopes (RFC 9068 §2.2 form).
	Scope string `json:"scope,omitempty"`
}

// AccessTokenInput collects the values MintAccessToken needs.
type AccessTokenInput struct {
	// Issuer is the OP issuer URL (also the access-token audience).
	Issuer string
	// SubjectID is the op_user.id string.
	SubjectID string
	// ClientID is the RP the token was minted for.
	ClientID string
	// IssuedAt is the wall-clock issuance moment.
	IssuedAt time.Time
	// Expiry is the wall-clock expiry moment.
	Expiry time.Time
	// Scope is the granted scope set; serialized space-separated on the wire.
	Scope []string
}

// MintAccessToken signs the access token as a JWT (RFC 9068-style) with
// ES256 and the active kid in the JOSE header.
func MintAccessToken(in AccessTokenInput, priv *ecdsa.PrivateKey, kid string) (string, error) {
	claims := AccessTokenClaims{
		Issuer:   in.Issuer,
		Subject:  in.SubjectID,
		Audience: in.Issuer,
		Expiry:   in.Expiry.Unix(),
		IssuedAt: in.IssuedAt.Unix(),
		ClientID: in.ClientID,
		Scope:    strings.Join(in.Scope, " "),
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid),
	)
	if err != nil {
		return "", fmt.Errorf("oidc: build access-token signer: %w", err)
	}

	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("oidc: sign access token: %w", err)
	}

	return out, nil
}
