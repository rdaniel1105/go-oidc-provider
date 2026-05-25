package oidc

import (
	"fmt"
	"slices"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

// AuthorizeRequest carries the validated set of /oidc/authorize parameters.
// String-typed because the wire is form-encoded; downstream code converts
// to typed values once a client has been resolved.
type AuthorizeRequest struct {
	// ClientID is the client_id form parameter (required).
	ClientID string
	// RedirectURI is the redirect_uri form parameter (required). Must
	// match the client's registered redirect_uris exactly.
	RedirectURI string
	// ResponseType is the response_type form parameter (required, must
	// equal "code").
	ResponseType string
	// Scope is the parsed scope form parameter (required, must include
	// "openid").
	Scope []string
	// State is the OAuth state parameter. Optional on the wire, but RPs
	// that omit it lose CSRF protection — we echo whatever they send.
	State string
	// CodeChallenge is the PKCE code_challenge parameter (required for
	// this OP — every auth-code client uses PKCE, including confidential
	// clients).
	CodeChallenge string
	// CodeChallengeMethod is the PKCE code_challenge_method parameter
	// (required, must equal "S256").
	CodeChallengeMethod string
	// Nonce is the OIDC nonce parameter, echoed into the ID token.
	Nonce string
	// ACRValues is the parsed acr_values form parameter (optional).
	ACRValues []string
	// LoginHint is the optional login_hint form parameter.
	LoginHint string
}

// AuthorizeErrorCode is one of the OAuth 2.0 / OIDC standard error codes
// the OP emits at /oidc/authorize. The set is intentionally narrow.
type AuthorizeErrorCode string

const (
	// AuthorizeErrInvalidRequest signals malformed or missing required
	// parameters. Maps to OAuth `invalid_request`.
	AuthorizeErrInvalidRequest AuthorizeErrorCode = "invalid_request"
	// AuthorizeErrUnauthorizedClient signals a client that is not allowed
	// to use the requested grant or response type.
	AuthorizeErrUnauthorizedClient AuthorizeErrorCode = "unauthorized_client"
	// AuthorizeErrInvalidScope signals a scope the client may not request.
	AuthorizeErrInvalidScope AuthorizeErrorCode = "invalid_scope"
	// AuthorizeErrUnsupportedResponseType signals response_type other than "code".
	AuthorizeErrUnsupportedResponseType AuthorizeErrorCode = "unsupported_response_type"
	// AuthorizeErrServerError signals an unexpected internal failure.
	AuthorizeErrServerError AuthorizeErrorCode = "server_error"
)

// ErrAuthorize is the typed error returned by ValidateAuthorizeRequest.
// The Code field maps to the OAuth error code; SafeRedirect indicates
// whether the OP may safely send the user back to the requested
// redirect_uri carrying ?error=... (only true once client_id and
// redirect_uri have been verified).
type ErrAuthorize struct {
	// Code is the OAuth error identifier.
	Code AuthorizeErrorCode
	// Description is the human-readable detail. Safe to render to the
	// user — derived from sentinel cases, not from untrusted input.
	Description string
	// SafeRedirect is true when the OP has confirmed both client_id and
	// redirect_uri are valid registrations, so the error can be returned
	// to the RP via a redirect. When false the error must be rendered as
	// an HTML page; redirecting would create an open redirector.
	SafeRedirect bool
}

// Error implements the error interface.
func (e *ErrAuthorize) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("authorize: %s", e.Code)
	}
	return fmt.Sprintf("authorize: %s: %s", e.Code, e.Description)
}

// ValidateAuthorizeRequest checks req against the resolved client and
// returns an ErrAuthorize on the first failure. The check order is
// deliberate: client + redirect_uri first (because everything after must
// be reportable via redirect), then the parameter shape, then the scope.
//
// The function does not generate or store anything — callers persist the
// validated request and mint codes themselves.
func ValidateAuthorizeRequest(req AuthorizeRequest, client *domain.Client) error {
	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return &ErrAuthorize{
			Code:         AuthorizeErrInvalidRequest,
			Description:  "redirect_uri is not registered for this client",
			SafeRedirect: false,
		}
	}

	if !slices.Contains(client.GrantTypes, "authorization_code") {
		return &ErrAuthorize{
			Code:         AuthorizeErrUnauthorizedClient,
			Description:  "client is not allowed to use the authorization_code grant",
			SafeRedirect: true,
		}
	}

	if req.ResponseType != "code" {
		return &ErrAuthorize{
			Code:         AuthorizeErrUnsupportedResponseType,
			Description:  "only response_type=code is supported",
			SafeRedirect: true,
		}
	}

	if len(client.ResponseTypes) > 0 && !slices.Contains(client.ResponseTypes, req.ResponseType) {
		return &ErrAuthorize{
			Code:         AuthorizeErrUnauthorizedClient,
			Description:  "client is not allowed to use this response_type",
			SafeRedirect: true,
		}
	}

	if req.CodeChallenge == "" {
		return &ErrAuthorize{
			Code:         AuthorizeErrInvalidRequest,
			Description:  "code_challenge is required",
			SafeRedirect: true,
		}
	}

	if req.CodeChallengeMethod != "S256" {
		return &ErrAuthorize{
			Code:         AuthorizeErrInvalidRequest,
			Description:  "code_challenge_method must be S256",
			SafeRedirect: true,
		}
	}

	if len(req.Scope) == 0 || !slices.Contains(req.Scope, "openid") {
		return &ErrAuthorize{
			Code:         AuthorizeErrInvalidScope,
			Description:  "scope must include openid",
			SafeRedirect: true,
		}
	}

	for _, s := range req.Scope {
		if !slices.Contains(client.Scopes, s) {
			return &ErrAuthorize{
				Code:         AuthorizeErrInvalidScope,
				Description:  fmt.Sprintf("scope %q is not allowed for this client", s),
				SafeRedirect: true,
			}
		}
	}

	return nil
}

