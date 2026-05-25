package domain

// AuthSession is the in-flight /oidc/authorize state held between the
// initial browser hit and the corresponding login-completion callback.
// It carries everything required to mint an authorization code after the
// user proves themselves with a passkey, so the login page itself can be
// pure HTML + a single submit — none of these parameters need to survive
// in the URL after the redirect.
type AuthSession struct {
	// ClientID is the RP the browser is authenticating against.
	ClientID string
	// RedirectURI is the validated redirect_uri to send the final code to.
	RedirectURI string
	// Scope is the validated scope set the user is consenting to.
	Scope []string
	// State is the OAuth state value to echo on the final redirect.
	State string
	// CodeChallenge is the PKCE challenge committed by the RP.
	CodeChallenge string
	// CodeChallengeMethod is the PKCE method (always "S256").
	CodeChallengeMethod string
	// Nonce is the OIDC nonce to embed in the resulting ID token.
	Nonce string
	// ACRValues is the requested acr_values list.
	ACRValues []string
	// LoginHint is the optional login_hint to pre-fill on the login page.
	LoginHint string
}
