package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuthCode is the at-rest payload behind a one-shot authorization code.
// It captures everything /oidc/token needs to mint a token pair after the
// browser flow completes: who the RP is, who the user is, the redirect
// URI to echo back, the requested scope/nonce, and the PKCE challenge
// the RP committed to.
type AuthCode struct {
	// ClientID is the RP this code was issued to.
	ClientID string
	// OPUserID is the op_user the browser authenticated as.
	OPUserID uuid.UUID
	// RedirectURI is the redirect_uri value the RP submitted at /authorize.
	// It must be echoed verbatim when the code is exchanged at /token.
	RedirectURI string
	// Scope is the set of scope values the RP requested and the user
	// (implicitly or explicitly) consented to.
	Scope []string
	// CodeChallenge is the PKCE code_challenge value committed at /authorize.
	CodeChallenge string
	// CodeChallengeMethod names the PKCE method. Only "S256" is supported
	// (advertised in discovery as the sole accepted method).
	CodeChallengeMethod string
	// Nonce is the OIDC nonce parameter the RP supplied. Echoed into the
	// resulting ID token to bind the token to the original request.
	Nonce string
	// ACR is the Authentication Context Class Reference value to emit in
	// the resulting ID token (e.g. "urn:passkey" for a passkey login).
	ACR string
	// AMR is the Authentication Methods References list to emit in the
	// resulting ID token (e.g. ["webauthn", "user"]).
	AMR []string
	// IssuedAt is the moment /authorize minted the code. Used as the lower
	// bound for the `auth_time` claim and for log triage.
	IssuedAt time.Time
}
