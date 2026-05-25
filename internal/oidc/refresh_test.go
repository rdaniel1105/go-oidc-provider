package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRefreshToken_DistinctRawAndHash(t *testing.T) {
	c := require.New(t)

	raw, hash, err := NewRefreshToken()
	c.NoError(err)
	c.NotEmpty(raw)
	c.NotEmpty(hash)
	c.NotEqual(raw, hash)
	c.Len(hash, 64, "sha256 hex is 64 chars")
}

func TestNewRefreshToken_HashDeterministic(t *testing.T) {
	c := require.New(t)

	raw, hash, err := NewRefreshToken()
	c.NoError(err)
	c.Equal(hash, HashRefreshToken(raw))
}

func TestNewRefreshToken_FreshEachCall(t *testing.T) {
	c := require.New(t)

	a, _, err := NewRefreshToken()
	c.NoError(err)
	b, _, err := NewRefreshToken()
	c.NoError(err)
	c.NotEqual(a, b)
}
