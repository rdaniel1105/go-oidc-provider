// Package domain holds the core entities used across the OP — Client,
// OPUser, RefreshToken — and the sentinel errors returned by the store layer.
// Handlers and services depend on this package; the store packages depend
// on it for the error contract.
package domain

import "errors"

// Sentinel errors returned by stores. Match with errors.Is.
var (
	// ErrClientNotFound is returned when a client lookup finds no live row.
	// Soft-deleted clients are treated as not found.
	ErrClientNotFound = errors.New("client not found")
	// ErrClientIDTaken is returned when registering a client whose client_id
	// already exists among live (non-deleted) rows.
	ErrClientIDTaken = errors.New("client_id already taken")

	// ErrOPUserNotFound is returned when an op_user lookup finds no live row.
	ErrOPUserNotFound = errors.New("op_user not found")
	// ErrEmailTaken is returned when creating an op_user whose email already
	// exists among live rows.
	ErrEmailTaken = errors.New("email already taken")
	// ErrPhoneTaken is returned when creating an op_user whose phone_e164
	// already exists among live rows.
	ErrPhoneTaken = errors.New("phone already taken")
	// ErrPasskeyUserIDTaken is returned when creating an op_user whose
	// passkey_user_id is already linked to another live op_user. The
	// passkey service's user is meant to map to exactly one OP identity.
	ErrPasskeyUserIDTaken = errors.New("passkey_user_id already linked")

	// ErrRefreshTokenNotFound is returned when a refresh-token hash lookup
	// finds no row. Callers MUST treat this as a hard rejection — it is
	// indistinguishable from a forged token and not an opportunity to
	// retry.
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	// ErrRefreshTokenHashTaken is returned when inserting a refresh token
	// whose hash already exists. In practice this only happens if the
	// token generator collides on 256 bits of randomness, so a returned
	// value here is closer to "internal error" than a user-facing
	// condition; callers should retry with a freshly generated token.
	ErrRefreshTokenHashTaken = errors.New("refresh token hash already taken")
)
