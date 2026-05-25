package domain

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken is the at-rest record for a refresh-token grant. The raw
// token is never stored — TokenHash is the hex SHA-256 of the URL-safe
// string handed to the RP. Issuance, expiry, and revocation timestamps
// support the rotation-on-use flow without needing a separate table.
type RefreshToken struct {
	// ID is the internal row identifier.
	ID uuid.UUID
	// TokenHash is the lowercase hex SHA-256 of the bearer string the RP
	// holds. Unique across the entire table.
	TokenHash string
	// ClientID is the client_id of the RP this token was issued to. Not
	// the clients.id UUID — TEXT identifier so revocations follow YAML
	// reconciliation.
	ClientID string
	// OPUserID is the op_user whose authentication backs the token.
	OPUserID uuid.UUID
	// FamilyID groups every refresh token descended from the same
	// initial authentication. Rotation copies this value from parent to
	// child; replay of a revoked token triggers a family-wide revocation
	// so the attacker's chain is broken without affecting other
	// concurrent sessions for the same user.
	FamilyID uuid.UUID
	// Scope is the set of scopes the token can be exchanged for. The
	// access token minted from a refresh exchange is bounded by this
	// list (the RP may narrow it; widening is rejected).
	Scope []string
	// AuthTime is the moment the user proved themselves with a passkey
	// at the start of this token's family. Carried through every
	// rotation so refreshed ID tokens still report the original
	// authentication moment.
	AuthTime time.Time
	// IssuedAt is the row creation timestamp.
	IssuedAt time.Time
	// ExpiresAt is the wall-clock expiry. Tokens past this point are
	// rejected at /token even if not explicitly revoked.
	ExpiresAt time.Time
	// RevokedAt is the wall-clock revocation timestamp. Nil for live
	// tokens; set by rotation, by client-driven revoke, or by family-wide
	// revocation when a stolen token is detected.
	RevokedAt *time.Time
}

// IsRevoked reports whether the token has been explicitly revoked.
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsExpired reports whether the token's expiry timestamp has passed
// relative to the supplied now.
func (t *RefreshToken) IsExpired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}
