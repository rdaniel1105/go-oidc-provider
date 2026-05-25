package domain

import (
	"time"

	"github.com/google/uuid"
)

// CIBAStatus names the lifecycle state of a CIBA backchannel
// authentication request. Once a request leaves Pending it stays in its
// terminal state until the TTL expires.
type CIBAStatus string

const (
	// CIBAStatusPending is the initial state, emitted by /oidc/bc-authorize.
	// Polls at /oidc/token return `authorization_pending` while in this
	// state.
	CIBAStatusPending CIBAStatus = "pending"
	// CIBAStatusApproved is set when the user completes the passkey
	// ceremony on /ciba/approve. Polls return tokens.
	CIBAStatusApproved CIBAStatus = "approved"
	// CIBAStatusDenied is set when the user declines on /ciba/deny.
	// Polls return `access_denied`.
	CIBAStatusDenied CIBAStatus = "denied"
)

// CIBARequest is the at-rest payload behind an auth_req_id. It carries
// everything the polling token endpoint and the approval page need: who
// asked, who must approve, what scopes are being requested, the binding
// message displayed to the user, and the RP-side correlation token to
// echo at ping/push delivery time.
type CIBARequest struct {
	// ClientID is the RP that opened the request.
	ClientID string
	// OPUserID is the op_user resolved from the login_hint at request time.
	OPUserID uuid.UUID
	// Scope is the set of scope values the RP requested.
	Scope []string
	// BindingMessage is the human-readable transaction description shown
	// on the approval page. Truncated to 200 chars at request time.
	BindingMessage string
	// ACRValues is the requested acr_values list (e.g. ["urn:passkey"]).
	// Used to gate which authentication mechanism satisfies the request.
	ACRValues []string
	// ClientNotificationToken is the RP-side correlation identifier. The OP
	// echoes it back when delivering tokens via ping/push.
	ClientNotificationToken string
	// Status is the current lifecycle state.
	Status CIBAStatus
	// IssuedAt is the moment /bc-authorize minted the request.
	IssuedAt time.Time
	// ApprovedAt is set to the approval moment when Status flips to
	// approved.
	ApprovedAt *time.Time
	// DeniedAt is set to the denial moment when Status flips to denied.
	DeniedAt *time.Time
}
