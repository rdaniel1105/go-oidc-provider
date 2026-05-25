package oidc

import (
	"crypto/ecdsa"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IDTokenClaims is the OIDC ID Token claim set this OP emits. Only the
// claims the OP actually populates are present; missing claims are not
// sent on the wire (omitempty on optional fields).
type IDTokenClaims struct {
	// Issuer matches the OP's configured issuer URL.
	Issuer string `json:"iss"`
	// Subject is the op_user identifier — stable per user, opaque to RPs.
	Subject string `json:"sub"`
	// Audience is the client_id of the RP the token is being issued to.
	Audience string `json:"aud"`
	// Expiry is the unix-seconds expiry time.
	Expiry int64 `json:"exp"`
	// IssuedAt is the unix-seconds issuance time.
	IssuedAt int64 `json:"iat"`
	// AuthTime is the unix-seconds moment the user actually authenticated.
	// For auth-code flows this is the /authorize completion time, not
	// /token exchange.
	AuthTime int64 `json:"auth_time,omitempty"`
	// Nonce is the value the RP supplied at /authorize, echoed verbatim.
	Nonce string `json:"nonce,omitempty"`
	// ACR is the authentication context class reference
	// (e.g. "urn:passkey").
	ACR string `json:"acr,omitempty"`
	// AMR is the authentication methods references list
	// (e.g. ["webauthn", "user"]).
	AMR []string `json:"amr,omitempty"`
	// Email is included when the openid scope was paired with `email`.
	Email string `json:"email,omitempty"`
	// EmailVerified mirrors the OIDC standard claim. This OP only stores
	// emails for users who successfully completed a passkey ceremony, so
	// the value is fixed to true today.
	EmailVerified *bool `json:"email_verified,omitempty"`
	// Name is included when the openid scope was paired with `profile`.
	Name string `json:"name,omitempty"`
}

// IDTokenInput collects everything MintIDToken needs to build the claim
// set. Splitting this from the claims struct keeps the wire shape
// JSON-clean and the inputs readable in handler code.
type IDTokenInput struct {
	// Issuer is the OP issuer URL.
	Issuer string
	// SubjectID is the op_user.id string.
	SubjectID string
	// Audience is the client_id of the RP.
	Audience string
	// IssuedAt is the wall-clock issuance moment.
	IssuedAt time.Time
	// Expiry is the wall-clock expiry moment.
	Expiry time.Time
	// AuthTime is the wall-clock authentication moment.
	AuthTime time.Time
	// Nonce is the RP's nonce parameter.
	Nonce string
	// ACR is the authentication context class reference.
	ACR string
	// AMR is the authentication methods references.
	AMR []string
	// Scope is the granted scope set. Determines which optional claims
	// (email, profile) are populated.
	Scope []string
	// Email is the user's email; emitted when "email" is in scope.
	Email string
	// Name is the user's display name; emitted when "profile" is in scope.
	Name string
}

// MintIDToken signs an OIDC ID Token JWS using the given ES256 key. The
// kid header is set so RPs can locate the matching public key in the JWKS.
func MintIDToken(in IDTokenInput, priv *ecdsa.PrivateKey, kid string) (string, error) {
	claims := IDTokenClaims{
		Issuer:   in.Issuer,
		Subject:  in.SubjectID,
		Audience: in.Audience,
		Expiry:   in.Expiry.Unix(),
		IssuedAt: in.IssuedAt.Unix(),
		AuthTime: in.AuthTime.Unix(),
		Nonce:    in.Nonce,
		ACR:      in.ACR,
		AMR:      in.AMR,
	}

	if containsScope(in.Scope, "email") && in.Email != "" {
		claims.Email = in.Email
		verified := true
		claims.EmailVerified = &verified
	}

	if containsScope(in.Scope, "profile") && in.Name != "" {
		claims.Name = in.Name
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return "", fmt.Errorf("oidc: build id-token signer: %w", err)
	}

	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("oidc: sign id token: %w", err)
	}

	return out, nil
}

// containsScope reports whether the scope slice contains s.
func containsScope(scope []string, s string) bool {
	for _, v := range scope {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
