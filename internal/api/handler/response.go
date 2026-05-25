package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// errorEnvelope is the wire shape used for every error response: a stable
// machine-readable code paired with an optional human-readable description.
// Keeping the shape uniform across endpoints lets RP-side clients use one
// decoder for every error path.
type errorEnvelope struct {
	// Code is the stable error identifier (e.g. "invalid_request",
	// "email_taken"). RPs should match on this.
	Code string `json:"error"`
	// Description is an optional human-readable explanation. Never include
	// untrusted input verbatim — only sentinel-derived prose.
	Description string `json:"error_description,omitempty"`
}

// writeJSON encodes body as JSON and writes it with the given status code.
// Encoding failures are logged but cannot be reported to the client at that
// point (status is already on the wire), so they are silently dropped.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if body == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.Error("encode response", "err", err)
	}
}

// writeError writes a stable error envelope with the given status, code,
// and optional description. Use writeError exclusively at HTTP boundaries
// so raw error strings from internal packages never leak to clients.
func writeError(w http.ResponseWriter, logger *slog.Logger, status int, code, description string) {
	writeJSON(w, logger, status, errorEnvelope{Code: code, Description: description})
}
