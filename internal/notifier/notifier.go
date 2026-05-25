// Package notifier delivers the CIBA approval link to the user's
// authentication device. The interface is the contract; the OP picks an
// implementation (log, telegram, whatsapp, webhook) per deployment by
// configuration. Adding a channel means adding one Notifier
// implementation — no CIBA-flow code changes are required.
package notifier

import (
	"context"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

// Notification is the payload an AuthDeviceNotifier delivers to the
// user's device. The fields collapse the OP's view of "this user has a
// pending CIBA request" into something a channel can render.
type Notification struct {
	// User is the op_user the request is awaiting approval from. The
	// implementation reads delivery-channel-specific fields (email,
	// phone, chat id) off this row.
	User *domain.OPUser
	// ClientName is the human-readable name of the RP requesting
	// authorization, shown to the user as "Continuing to <ClientName>".
	ClientName string
	// BindingMessage is the transaction-specific message the RP supplied
	// at /bc-authorize. Already truncated to the OP's display cap.
	BindingMessage string
	// ApprovalURL is the single-use HTTPS URL the user opens to reach
	// the approval page. Treat as a bearer secret — anyone who can read
	// the URL can approve the request.
	ApprovalURL string
}

// AuthDeviceNotifier is the channel-agnostic delivery contract. An
// implementation MUST be safe to call concurrently from multiple
// goroutines; the CIBA handler spawns one Notify per /bc-authorize call.
type AuthDeviceNotifier interface {
	// Notify delivers the approval URL to the user's device. The error
	// path is for transport / authentication failures — the CIBA flow
	// uses it to decide whether to surface a synchronous error on the
	// /bc-authorize response or accept the call optimistically.
	Notify(ctx context.Context, n Notification) error
}
