package oidc

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Sentinel errors returned by VerifyAccessToken. UserInfo and any other
// Bearer-protected endpoint map both to 401 with `WWW-Authenticate:
// Bearer error="invalid_token"`; the distinction is only for logs and
// rate-limiting heuristics.
var (
	// ErrAccessTokenInvalid is returned for malformed tokens, unknown
	// signing keys, signature mismatches, or claim shapes that don't
	// match this OP.
	ErrAccessTokenInvalid = errors.New("oidc: access token invalid")
	// ErrAccessTokenExpired is returned when iat/exp checks place the
	// token outside its validity window.
	ErrAccessTokenExpired = errors.New("oidc: access token expired")
)

// PublicKeyResolver returns the public key bound to a kid, or
// ErrUnknownKID if no such key is loaded. *KeyStore satisfies this.
type PublicKeyResolver interface {
	PublicKeyByKID(kid string) (*ecdsa.PublicKey, error)
}

// VerifyAccessToken parses and verifies an at+jwt access token. On
// success it returns the decoded claims. The token must be signed with
// ES256, carry a kid the resolver recognizes, claim iss and aud equal to
// the OP's issuer, and have an iat/exp window that contains now (a small
// leeway absorbs clock skew).
//
// VerifyAccessToken does NOT check scope. Callers decide which claims to
// emit based on the granted scope returned in the claim set.
func VerifyAccessToken(token string, resolver PublicKeyResolver, issuer string, now time.Time) (*AccessTokenClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrAccessTokenInvalid, err)
	}

	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one JWS header", ErrAccessTokenInvalid)
	}

	header := parsed.Headers[0]
	if header.Algorithm != string(jose.ES256) {
		return nil, fmt.Errorf("%w: unexpected alg %q", ErrAccessTokenInvalid, header.Algorithm)
	}
	if header.KeyID == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrAccessTokenInvalid)
	}

	pub, err := resolver.PublicKeyByKID(header.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAccessTokenInvalid, err)
	}

	var claims AccessTokenClaims
	if err := parsed.Claims(pub, &claims); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrAccessTokenInvalid, err)
	}

	if claims.Issuer != issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrAccessTokenInvalid)
	}

	if claims.Audience != issuer {
		return nil, fmt.Errorf("%w: audience mismatch", ErrAccessTokenInvalid)
	}

	const leeway = 30 * time.Second
	exp := time.Unix(claims.Expiry, 0)
	iat := time.Unix(claims.IssuedAt, 0)

	if !now.Before(exp.Add(leeway)) {
		return nil, ErrAccessTokenExpired
	}
	if now.Add(leeway).Before(iat) {
		return nil, fmt.Errorf("%w: token issued in the future", ErrAccessTokenInvalid)
	}

	return &claims, nil
}

// ScopeList parses the space-separated scope string returned in
// AccessTokenClaims.Scope back into a slice for caller inspection.
func ScopeList(scope string) []string {
	if scope == "" {
		return nil
	}
	out := []string{}
	start := 0
	for i := 0; i < len(scope); i++ {
		if scope[i] == ' ' {
			if i > start {
				out = append(out, scope[start:i])
			}
			start = i + 1
		}
	}
	if start < len(scope) {
		out = append(out, scope[start:])
	}
	return out
}
