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

// DiscoveryHandler serves the OIDC "well-known" endpoints (JWKS today,
// the discovery document in a later phase).
type DiscoveryHandler struct {
	keys   *oidc.KeyStore
	logger *slog.Logger
}

// NewDiscoveryHandler returns a DiscoveryHandler that exposes keys via JWKS.
func NewDiscoveryHandler(keys *oidc.KeyStore, logger *slog.Logger) *DiscoveryHandler {
	return &DiscoveryHandler{keys: keys, logger: logger}
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
