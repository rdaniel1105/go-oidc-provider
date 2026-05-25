// Package handler implements the HTTP endpoints exposed by the OP. Handlers
// stay thin: they unwrap the request, call into the protocol packages
// (oidc, ciba, passkey), and shape the response. Business logic lives below.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

// DiscoveryHandler serves the OIDC "well-known" endpoints: the OpenID Provider
// configuration document and the JSON Web Key Set used to verify ID tokens.
type DiscoveryHandler struct {
	keys   *oidc.KeyStore
	doc    oidc.DiscoveryDocument
	logger *slog.Logger
}

// NewDiscoveryHandler returns a DiscoveryHandler bound to the given key store
// and a pre-built discovery document. The document is static for the lifetime
// of the process; rebuild and reconstruct the handler if the issuer changes.
func NewDiscoveryHandler(keys *oidc.KeyStore, doc oidc.DiscoveryDocument, logger *slog.Logger) *DiscoveryHandler {
	return &DiscoveryHandler{keys: keys, doc: doc, logger: logger}
}

// OpenIDConfiguration serves GET /.well-known/openid-configuration with the
// OpenID Provider metadata. The document is cached for an hour; rotation of
// scopes or grants would require a coordinated cache-bust on the RP side, so
// the long TTL is paired with a deploy-time intent to only change this doc
// when adding capability (never removing it silently).
func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if err := json.NewEncoder(w).Encode(h.doc); err != nil {
		h.logger.Error("encode discovery document", "err", err)
	}
}

// JWKS serves GET /.well-known/jwks.json with the public JWKs of every
// signing key currently held by the OP. Browsers and RP libraries cache the
// response per Cache-Control; rotation is communicated by changing the active
// kid rather than evicting old entries, so a 5-minute cache is safe.
func (h *DiscoveryHandler) JWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := h.keys.PublicJWKS()

	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Error("encode jwks", "err", err)
	}
}
