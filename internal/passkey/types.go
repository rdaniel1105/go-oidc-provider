package passkey

import "encoding/json"

// BeginRegisterRequest is the body of POST /auth/register/begin.
type BeginRegisterRequest struct {
	// Username is the passkey-side username for the new user. The OP
	// passes its op_user.id as this value so the passkey service holds no
	// PII keyed identifier; the join back to the OP record happens through
	// op_users.passkey_user_id, not username matching.
	Username string `json:"username"`
	// DisplayName is the human-readable label shown in browser passkey UI
	// during the registration prompt.
	DisplayName string `json:"display_name"`
}

// BeginRegisterResponse is the body of a successful /auth/register/begin
// response. Options is opaque WebAuthn CreationOptions JSON that the
// browser passes to navigator.credentials.create; SessionID is the handle
// the caller submits at /auth/register/complete to reach the same
// server-side challenge state.
type BeginRegisterResponse struct {
	// Options is the PublicKeyCredentialCreationOptions wire payload.
	Options json.RawMessage `json:"options"`
	// SessionID ties the begin and complete calls together.
	SessionID string `json:"session_id"`
}

// CompleteRegisterRequest is the body of POST /auth/register/complete.
type CompleteRegisterRequest struct {
	// SessionID is the value returned by BeginRegister.
	SessionID string `json:"session_id"`
	// Credential is the AuthenticatorAttestationResponse JSON the browser
	// produced from navigator.credentials.create.
	Credential json.RawMessage `json:"credential"`
}

// CompleteRegisterResponse is the body of a successful
// /auth/register/complete response.
type CompleteRegisterResponse struct {
	// CredentialID is the persisted credential's external identifier.
	// Useful for audit logs; the OP does not currently key any of its own
	// records by this value.
	CredentialID string `json:"credential_id"`
}

// BeginLoginResponse is the body of a successful /auth/login/begin
// response. The wire shape mirrors BeginRegisterResponse but the Options
// payload is PublicKeyCredentialRequestOptions instead of creation
// options.
type BeginLoginResponse struct {
	// Options is the PublicKeyCredentialRequestOptions wire payload.
	Options json.RawMessage `json:"options"`
	// SessionID ties the begin and complete calls together.
	SessionID string `json:"session_id"`
}

// CompleteLoginRequest is the body of POST /auth/login/complete.
type CompleteLoginRequest struct {
	// SessionID is the value returned by BeginLogin.
	SessionID string `json:"session_id"`
	// Credential is the AuthenticatorAssertionResponse JSON the browser
	// produced from navigator.credentials.get.
	Credential json.RawMessage `json:"credential"`
}

// CompleteLoginResponse is the body of a successful /auth/login/complete
// response. UserID is the passkey-side user identifier the OP joins to
// op_users.passkey_user_id; Username and DisplayName are included for
// log triage and are not load-bearing for the OP's flow.
type CompleteLoginResponse struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}
