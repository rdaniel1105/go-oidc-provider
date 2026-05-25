package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewKeyStore_GeneratesInitialKey(t *testing.T) {
	c := require.New(t)

	dir := t.TempDir()
	store, err := NewKeyStore(dir, discardLogger())
	c.NoError(err)

	kid, priv, err := store.Active()
	c.NoError(err)
	c.NotEmpty(kid)
	c.NotNil(priv)
	c.Equal(elliptic.P256(), priv.Curve)

	matches, err := filepath.Glob(filepath.Join(dir, signingKeyFilePrefix+"*.pem"))
	c.NoError(err)
	c.Len(matches, 1)
	c.Contains(matches[0], kid)
}

func TestNewKeyStore_LoadsExistingKey(t *testing.T) {
	c := require.New(t)

	dir := t.TempDir()
	first, err := NewKeyStore(dir, discardLogger())
	c.NoError(err)
	firstKID, _, err := first.Active()
	c.NoError(err)

	second, err := NewKeyStore(dir, discardLogger())
	c.NoError(err)
	secondKID, _, err := second.Active()
	c.NoError(err)

	c.Equal(firstKID, secondKID, "kid must be stable across restarts")
	c.Len(second.PublicJWKS().Keys, 1)
}

func TestNewKeyStore_PicksLexicographicallyLargestActive(t *testing.T) {
	c := require.New(t)

	dir := t.TempDir()
	writeKeyFile(t, dir, "aa00000000000000000000000000000000")
	writeKeyFile(t, dir, "ff00000000000000000000000000000000")
	writeKeyFile(t, dir, "5500000000000000000000000000000000")

	store, err := NewKeyStore(dir, discardLogger())
	c.NoError(err)

	jwks := store.PublicJWKS()
	c.Len(jwks.Keys, 3)

	// The on-disk kid in the filename is not actually used as the in-memory kid
	// (the in-memory kid is recomputed from the public key bytes). What we are
	// asserting here is that all three keys load cleanly and that Active picks
	// the largest *recomputed* kid — every load must converge on the same
	// active key regardless of file-discovery order.
	wantActive := largestKID(jwks)
	gotActive, _, err := store.Active()
	c.NoError(err)
	c.Equal(wantActive, gotActive)
}

func TestPublicJWKS_ShapeIsSpecCompliant(t *testing.T) {
	c := require.New(t)

	dir := t.TempDir()
	store, err := NewKeyStore(dir, discardLogger())
	c.NoError(err)

	jwks := store.PublicJWKS()
	c.Len(jwks.Keys, 1)

	jwk := jwks.Keys[0]
	c.Equal(string(jose.ES256), jwk.Algorithm)
	c.Equal("sig", jwk.Use)
	c.NotEmpty(jwk.KeyID)
	c.False(jwk.IsPublic() == false, "JWK must serialize as a public key")

	_, ok := jwk.Key.(*ecdsa.PublicKey)
	c.True(ok, "JWK key must be *ecdsa.PublicKey")
}

func TestLoadKeyFile_RejectsNonP256(t *testing.T) {
	c := require.New(t)

	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	c.NoError(err)

	path := filepath.Join(dir, signingKeyFilePrefix+"badcurve.pem")
	writePKCS8PEM(t, path, priv)

	_, err = NewKeyStore(dir, discardLogger())
	c.Error(err)
	c.Contains(err.Error(), "P-256")
}

func writeKeyFile(t *testing.T, dir, kidStub string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	path := filepath.Join(dir, signingKeyFilePrefix+kidStub+".pem")
	writePKCS8PEM(t, path, priv)
}

func writePKCS8PEM(t *testing.T, path string, priv *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
}

func largestKID(jwks jose.JSONWebKeySet) string {
	var max string
	for _, k := range jwks.Keys {
		if k.KeyID > max {
			max = k.KeyID
		}
	}
	return max
}
