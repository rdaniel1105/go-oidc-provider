package domain

import (
	"time"

	"github.com/google/uuid"
)

// OPUser is the OP's authoritative record of an end user. It owns the
// OIDC-facing identity fields (email, phone, display name) and references
// the passkey service's user row via PasskeyUserID so the WebAuthn ceremony
// can be delegated without duplicating credential bindings here.
type OPUser struct {
	// ID is the internal row identifier and the value emitted as the `sub`
	// claim in ID tokens.
	ID uuid.UUID
	// Email is the CIBA login_hint target and the value emitted as the
	// `email` claim. Unique among live rows.
	Email string
	// DisplayName is the human-readable name shown in consent UIs and
	// emitted as the `name` claim.
	DisplayName string
	// PhoneE164 is the WhatsApp / SMS delivery target in E.164 format
	// (e.g. "+573001234567"). Nil for users with no phone channel
	// registered. Unique among live rows when present.
	PhoneE164 *string
	// PasskeyUserID is the foreign reference into go-passkey-auth's users
	// table. The OP does not enforce referential integrity to the passkey
	// service at the database level (separate databases); integrity is a
	// service-layer concern.
	PasskeyUserID uuid.UUID
	// CreatedAt is the row creation timestamp.
	CreatedAt time.Time
}
