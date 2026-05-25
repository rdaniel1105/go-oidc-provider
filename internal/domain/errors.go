// Package domain holds the core entities used across the OP — Client,
// OPUser, RefreshToken — and the sentinel errors returned by the store layer.
// Handlers and services depend on this package; the store packages depend
// on it for the error contract.
package domain

import "errors"

// Sentinel errors returned by stores. Match with errors.Is.
var (
	// ErrClientNotFound is returned when a client lookup finds no live row.
	// Soft-deleted clients are treated as not found.
	ErrClientNotFound = errors.New("client not found")
	// ErrClientIDTaken is returned when registering a client whose client_id
	// already exists among live (non-deleted) rows.
	ErrClientIDTaken = errors.New("client_id already taken")
)
