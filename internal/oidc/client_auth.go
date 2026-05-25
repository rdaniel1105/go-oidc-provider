package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

// ClientAuthErrorCode is one of the OAuth 2.0 token-endpoint error codes
// related to client authentication. The set is narrow on purpose; we use
// it where the wire shape demands a specific code.
type ClientAuthErrorCode string

const (
	// ClientAuthErrInvalidClient signals an unknown or unauthenticated
	// client. Maps to OAuth `invalid_client`.
	ClientAuthErrInvalidClient ClientAuthErrorCode = "invalid_client"
	// ClientAuthErrInvalidRequest signals malformed credentials (e.g.
	// Basic header that does not base64-decode).
	ClientAuthErrInvalidRequest ClientAuthErrorCode = "invalid_request"
)

// ClientAuthError is the typed error returned from AuthenticateClient.
type ClientAuthError struct {
	// Code is the OAuth error identifier.
	Code ClientAuthErrorCode
	// Description is a human-readable detail (no untrusted input).
	Description string
	// WWWAuthenticate, when non-empty, is the value the handler should
	// set on the `WWW-Authenticate` response header (per RFC 6749 §5.2,
	// invalid_client returns 401 with this header for Basic-authed
	// clients).
	WWWAuthenticate string
}

// Error implements the error interface.
func (e *ClientAuthError) Error() string {
	if e.Description == "" {
		return "client auth: " + string(e.Code)
	}
	return "client auth: " + string(e.Code) + ": " + e.Description
}

// ClientLookup is the slice of the client store AuthenticateClient needs.
// Kept as an interface so the token handler can mock it without a real DB.
type ClientLookup interface {
	GetByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// AuthenticateClient resolves the request to a registered client and
// verifies its credentials. The wire shape follows OIDC Core 1.0 §9 and
// the token endpoint sections of RFC 6749:
//
//   - client_secret_basic: HTTP Basic with client_id:client_secret
//   - client_secret_post:  client_id + client_secret in the form body
//   - none:                client_id in the form body, no secret
//
// Callers must have already called r.ParseForm before passing the
// request in — the form values are looked up directly.
//
// Returns a typed *ClientAuthError on failure; the token handler maps
// these to 400/401 with the appropriate WWW-Authenticate header.
func AuthenticateClient(ctx context.Context, r *http.Request, clients ClientLookup) (*domain.Client, error) {
	clientID, secret, method, err := extractCredentials(r)
	if err != nil {
		return nil, err
	}

	client, err := clients.GetByClientID(ctx, clientID)
	if errors.Is(err, domain.ErrClientNotFound) {
		return nil, &ClientAuthError{Code: ClientAuthErrInvalidClient, Description: "unknown client"}
	}
	if err != nil {
		return nil, err
	}

	if client.TokenEndpointAuthMethod != method {
		return nil, &ClientAuthError{
			Code:        ClientAuthErrInvalidClient,
			Description: "client is configured for " + string(client.TokenEndpointAuthMethod),
		}
	}

	if method == domain.AuthMethodNone {
		// Public clients carry no secret. PKCE is the protection.
		return client, nil
	}

	if client.ClientSecretHash == nil || *client.ClientSecretHash == "" {
		return nil, &ClientAuthError{
			Code:        ClientAuthErrInvalidClient,
			Description: "client has no secret on file but was authenticated as confidential",
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*client.ClientSecretHash), []byte(secret)); err != nil {
		return nil, &ClientAuthError{Code: ClientAuthErrInvalidClient, Description: "client secret mismatch"}
	}

	return client, nil
}

// extractCredentials pulls the client_id + secret + method off the
// request. Exactly one credential source must be present.
func extractCredentials(r *http.Request) (clientID, secret string, method domain.TokenEndpointAuthMethod, err error) {
	if header := r.Header.Get("Authorization"); header != "" {
		if !strings.HasPrefix(header, "Basic ") {
			return "", "", "", &ClientAuthError{
				Code:        ClientAuthErrInvalidRequest,
				Description: "only Basic authentication is supported at the token endpoint",
			}
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
		if decodeErr != nil {
			return "", "", "", &ClientAuthError{
				Code:            ClientAuthErrInvalidClient,
				Description:     "Authorization header is not valid base64",
				WWWAuthenticate: `Basic realm="oidc"`,
			}
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", "", &ClientAuthError{
				Code:            ClientAuthErrInvalidClient,
				Description:     "Authorization header is not client_id:client_secret",
				WWWAuthenticate: `Basic realm="oidc"`,
			}
		}
		return parts[0], parts[1], domain.AuthMethodClientSecretBasic, nil
	}

	clientID = r.PostForm.Get("client_id")
	if clientID == "" {
		return "", "", "", &ClientAuthError{
			Code:        ClientAuthErrInvalidClient,
			Description: "client_id is required",
		}
	}

	secret = r.PostForm.Get("client_secret")
	if secret == "" {
		return clientID, "", domain.AuthMethodNone, nil
	}

	return clientID, secret, domain.AuthMethodClientSecretPost, nil
}

// AsClientAuthError unwraps to *ClientAuthError. Returns nil if err is
// not of that type.
func AsClientAuthError(err error) *ClientAuthError {
	var cae *ClientAuthError
	if errors.As(err, &cae) {
		return cae
	}
	return nil
}
