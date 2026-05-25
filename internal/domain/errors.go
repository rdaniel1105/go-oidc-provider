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

	// ErrAuthCodeNotFound is returned when an authorization-code lookup
	// finds no entry (expired, never issued, or already consumed). Codes
	// are single-use, so Consume removes the entry as a side effect.
	ErrAuthCodeNotFound = errors.New("authorization code not found")

	// ErrCIBARequestNotFound is returned when an auth_req_id lookup finds
	// no entry (expired or never issued).
	ErrCIBARequestNotFound = errors.New("ciba request not found")
	// ErrCIBANotPending is returned when an approval or denial transition
	// is attempted on a request that is already in a terminal state. The
	// first writer wins; subsequent transitions are rejected.
	ErrCIBANotPending = errors.New("ciba request is not pending")

	// ErrApprovalTokenNotFound is returned when an approval-token lookup
	// finds no entry (expired, never issued, or already consumed).
	// Approval tokens are single-use.
	ErrApprovalTokenNotFound = errors.New("approval token not found")

	// ErrSignupStateNotFound is returned when a /users/complete call
	// references a session_id for which no signup payload remains
	// (expired, never issued, or already consumed).
	ErrSignupStateNotFound = errors.New("signup state not found")

	// ErrAuthSessionNotFound is returned when a /oidc/authorize login
	// callback references an auth_session_id with no entry (expired,
	// never issued, or already consumed). Auth sessions are single-use.
	ErrAuthSessionNotFound = errors.New("auth session not found")
)
