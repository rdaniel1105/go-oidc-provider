package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestJWKSHandler_ServesPublicKeys(t *testing.T) {
	c := require.New(t)

	dir := t.TempDir()
	store, err := oidc.NewKeyStore(dir, discardLogger())
	c.NoError(err)

	h := NewDiscoveryHandler(store, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.JWKS(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	c.Equal(http.StatusOK, res.StatusCode)
	c.Equal("application/jwk-set+json", res.Header.Get("Content-Type"))
	c.Contains(res.Header.Get("Cache-Control"), "max-age=300")

	var got jose.JSONWebKeySet
	c.NoError(json.NewDecoder(res.Body).Decode(&got))
	c.Len(got.Keys, 1)
	c.Equal("ES256", got.Keys[0].Algorithm)
	c.Equal("sig", got.Keys[0].Use)
	c.NotEmpty(got.Keys[0].KeyID)
}
