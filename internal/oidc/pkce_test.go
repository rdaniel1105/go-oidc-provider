package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyPKCE_KnownVector(t *testing.T) {
	c := require.New(t)

	// RFC 7636 §A.2 worked example.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	c.True(VerifyPKCE(verifier, challenge))
}

func TestVerifyPKCE_Mismatch(t *testing.T) {
	c := require.New(t)
	c.False(VerifyPKCE("wrong-verifier", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
}

func TestVerifyPKCE_EmptyInputs(t *testing.T) {
	c := require.New(t)
	c.False(VerifyPKCE("", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
	c.False(VerifyPKCE("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", ""))
	c.False(VerifyPKCE("", ""))
}
