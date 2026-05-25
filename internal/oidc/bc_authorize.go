package oidc

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

// CIBAGrantType is the grant_type value the token endpoint accepts for
// the CIBA flow. Used both in client allowlist validation here and at
// the eventual /oidc/token polling exchange.
const CIBAGrantType = "urn:openid:params:grant-type:ciba"

// Limits applied to /oidc/bc-authorize input. Centralized so the
// docs / tests / handler stay in lockstep.
const (
	// BindingMessageMaxLen caps how long a binding_message can be at
	// /bc-authorize. Notifier channels truncate further (WhatsApp
	// templates ~1024, phone screens give up around 200), so 200 is the
	// tightest sensible ceiling.
	BindingMessageMaxLen = 200
	// RequestedExpiryMin is the minimum requested_expiry the OP accepts.
	// Anything shorter is rejected as invalid_request — the user needs
	// at least a minute to read the message and tap the link.
	RequestedExpiryMin = 60
	// RequestedExpiryMax is the maximum requested_expiry the OP honors;
	// values above the cap are silently clamped per CIBA §7.1.
	RequestedExpiryMax = 900
)

// BCAuthorizeRequest is the parsed set of /oidc/bc-authorize form params
// the OP cares about. login_hint_token and id_token_hint are unsupported
// in v1 (login_hint is the only resolution path).
type BCAuthorizeRequest struct {
	// ClientID is resolved from the form or HTTP Basic by the client
	// authentication step before reaching the validator.
	ClientID string
	// Scope is the space-separated scope parameter, split into a slice.
	// Must include "openid" and must be a subset of the client's
	// configured scopes.
	Scope []string
	// LoginHint is the value the OP resolves to an op_user. Today this
	// is an email; other shapes (phone, sub) are not implemented.
	LoginHint string
	// BindingMessage is the transaction-specific message displayed on
	// the approval page. Capped at BindingMessageMaxLen runes.
	BindingMessage string
	// ACRValues is the requested acr_values list. The OP only emits
	// urn:passkey, so any other request value is rejected.
	ACRValues []string
	// ClientNotificationToken is the RP-side correlation identifier.
	// Required when the client is configured for ping/push delivery so
	// the OP can echo it back at delivery time.
	ClientNotificationToken string
	// RequestedExpiry is the RP's preferred CIBA request lifetime. The
	// OP clamps this to [RequestedExpiryMin, RequestedExpiryMax].
	RequestedExpiry int
}

// BCAuthorizeErrorCode is one of the CIBA §13 error codes the OP emits
// at /oidc/bc-authorize.
type BCAuthorizeErrorCode string

const (
	// BCErrInvalidRequest signals malformed or missing required params.
	BCErrInvalidRequest BCAuthorizeErrorCode = "invalid_request"
	// BCErrInvalidScope signals a scope the client may not request.
	BCErrInvalidScope BCAuthorizeErrorCode = "invalid_scope"
	// BCErrUnauthorizedClient signals a client that is not allowed to
	// use the CIBA grant.
	BCErrUnauthorizedClient BCAuthorizeErrorCode = "unauthorized_client"
	// BCErrUnknownUserID signals a login_hint that does not resolve to
	// any op_user.
	BCErrUnknownUserID BCAuthorizeErrorCode = "unknown_user_id"
	// BCErrInvalidBindingMessage signals a binding_message that exceeds
	// the OP's display cap or contains disallowed characters.
	BCErrInvalidBindingMessage BCAuthorizeErrorCode = "invalid_binding_message"
	// BCErrMissingUserCode is reserved for the CIBA user_code parameter
	// path the OP does not implement; included for completeness.
	BCErrMissingUserCode BCAuthorizeErrorCode = "missing_user_code"
)

// ErrBCAuthorize is the typed error returned from validation. The
// handler maps each Code to a 400 with the standard CIBA error envelope.
type ErrBCAuthorize struct {
	// Code is the CIBA error identifier.
	Code BCAuthorizeErrorCode
	// Description is the human-readable detail. Safe to surface verbatim
	// — derived from sentinel cases, not from untrusted input.
	Description string
}

// Error implements the error interface.
func (e *ErrBCAuthorize) Error() string {
	if e.Description == "" {
		return "bc-authorize: " + string(e.Code)
	}
	return "bc-authorize: " + string(e.Code) + ": " + e.Description
}

// ValidateBCAuthorizeRequest checks req against the resolved client and
// returns an ErrBCAuthorize on the first failure. It does NOT resolve
// the login_hint to an op_user; that is the caller's responsibility,
// since it requires a store lookup.
func ValidateBCAuthorizeRequest(req BCAuthorizeRequest, client *domain.Client) error {
	if !slices.Contains(client.GrantTypes, CIBAGrantType) {
		return &ErrBCAuthorize{
			Code:        BCErrUnauthorizedClient,
			Description: "client is not allowed to use the CIBA grant",
		}
	}

	if strings.TrimSpace(req.LoginHint) == "" {
		return &ErrBCAuthorize{
			Code:        BCErrInvalidRequest,
			Description: "login_hint is required",
		}
	}

	if len(req.Scope) == 0 || !slices.Contains(req.Scope, "openid") {
		return &ErrBCAuthorize{
			Code:        BCErrInvalidScope,
			Description: "scope must include openid",
		}
	}

	for _, s := range req.Scope {
		if !slices.Contains(client.Scopes, s) {
			return &ErrBCAuthorize{
				Code:        BCErrInvalidScope,
				Description: fmt.Sprintf("scope %q is not allowed for this client", s),
			}
		}
	}

	if strings.TrimSpace(req.BindingMessage) == "" {
		return &ErrBCAuthorize{
			Code:        BCErrInvalidBindingMessage,
			Description: "binding_message is required so the user knows what they are authorizing",
		}
	}

	if utf8.RuneCountInString(req.BindingMessage) > BindingMessageMaxLen {
		return &ErrBCAuthorize{
			Code:        BCErrInvalidBindingMessage,
			Description: fmt.Sprintf("binding_message must be %d characters or fewer", BindingMessageMaxLen),
		}
	}

	for _, acr := range req.ACRValues {
		if acr != "urn:passkey" {
			return &ErrBCAuthorize{
				Code:        BCErrInvalidRequest,
				Description: "this OP only supports acr=urn:passkey",
			}
		}
	}

	if client.BackchannelTokenDeliveryMode != nil && *client.BackchannelTokenDeliveryMode != domain.CIBADeliveryPoll {
		if strings.TrimSpace(req.ClientNotificationToken) == "" {
			return &ErrBCAuthorize{
				Code:        BCErrInvalidRequest,
				Description: "client_notification_token is required for ping/push delivery clients",
			}
		}
	}

	return nil
}

// ClampRequestedExpiry returns the effective TTL the OP will apply to a
// CIBA request given the RP's requested_expiry and the OP-side default.
// Zero or negative input falls through to the default; values outside
// the configured window are clamped to the nearest bound.
func ClampRequestedExpiry(requested int, defaultTTL time.Duration) time.Duration {
	if requested <= 0 {
		return defaultTTL
	}
	if requested < RequestedExpiryMin {
		return time.Duration(RequestedExpiryMin) * time.Second
	}
	if requested > RequestedExpiryMax {
		return time.Duration(RequestedExpiryMax) * time.Second
	}
	return time.Duration(requested) * time.Second
}

// TruncateBindingMessage returns msg truncated to BindingMessageMaxLen
// runes, with an ellipsis appended when truncation occurred. Caller
// runs this AFTER validation, so the validator's hard cap protects
// against the failure path and this only kicks in for callers that
// elect to relax the cap upstream.
func TruncateBindingMessage(msg string) string {
	if utf8.RuneCountInString(msg) <= BindingMessageMaxLen {
		return msg
	}
	runes := []rune(msg)
	return string(runes[:BindingMessageMaxLen-1]) + "…"
}
