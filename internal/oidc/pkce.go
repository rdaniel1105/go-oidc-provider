package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyPKCE returns true when the given code_verifier matches the
// code_challenge under the S256 method (per RFC 7636 §4.6). The
// comparison is constant-time so a timing-side-channel cannot learn the
// expected challenge bytes.
//
// The OP only supports S256; "plain" is intentionally not implemented
// and discovery does not advertise it.
func VerifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
