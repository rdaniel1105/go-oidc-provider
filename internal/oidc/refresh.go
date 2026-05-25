package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// NewRefreshToken returns a freshly generated URL-safe refresh token
// (32 random bytes, base64url-no-pad) alongside the lowercase hex SHA-256
// hash that should be persisted. The raw value is what is handed to the
// RP; the hash is what is stored.
func NewRefreshToken() (raw, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("oidc: read random: %w", err)
	}

	raw = base64.RawURLEncoding.EncodeToString(b[:])
	hash = HashRefreshToken(raw)
	return raw, hash, nil
}

// HashRefreshToken returns the lowercase hex SHA-256 hash of the raw
// refresh-token string. Use this both when persisting (issuance) and when
// looking up (rotation / introspection).
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
