package domain

// SignupState is the cross-request payload carried between POST /users
// (which initiates the passkey registration ceremony) and POST
// /users/complete (which finalizes it). It holds the form input the user
// submitted at /users so the OP can create the op_user row only after
// the authenticator has proven itself at /complete — abandoned ceremonies
// leave no row behind.
type SignupState struct {
	// Email is the address the user supplied. Will become the op_user.email
	// once the ceremony succeeds.
	Email string
	// DisplayName is the human-readable name the user supplied.
	DisplayName string
	// PhoneE164 is the optional WhatsApp / SMS delivery target.
	PhoneE164 *string
}
