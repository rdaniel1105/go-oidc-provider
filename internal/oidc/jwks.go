// Package oidc holds the OpenID Provider's protocol-level building blocks:
// signing keys, the JWKS document, token minting, and the discovery document.
package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	jose "github.com/go-jose/go-jose/v4"
)

// signingKeyFilePrefix is the prefix used for ES256 private-key files in
// the keys directory. The full filename is "<prefix><kid>.pem".
const signingKeyFilePrefix = "signing-"

// Sentinel errors returned by KeyStore operations.
var (
	// ErrNoActiveKey is returned when no signing key is loaded. NewKeyStore
	// generates one if the directory is empty, so seeing this in normal flow
	// means the store was constructed without the file-system bootstrap path.
	ErrNoActiveKey = errors.New("oidc: no active signing key")
	// ErrUnknownKID is returned by PublicKeyByKID when no loaded key
	// matches the supplied kid. Surfaces as an invalid_token at verifiers.
	ErrUnknownKID = errors.New("oidc: unknown kid")
)

// KeyStore holds the OP's ES256 signing material. It exposes the active
// private key for token signing and a JWKS view of all currently published
// public keys (active plus retired keys still inside the rotation window).
//
// KeyStore is read-mostly after construction. Rotation will mutate the slice
// in a later phase; for now NewKeyStore loads existing keys or generates one
// and the set is stable for the lifetime of the process.
type KeyStore struct {
	keys      []signingKey
	activeKID string
}

// signingKey pairs an ES256 private key with its key identifier. The kid is
// derived deterministically from the public key so it survives restarts and
// can be recomputed if the on-disk filename is lost.
type signingKey struct {
	kid  string
	priv *ecdsa.PrivateKey
}

// NewKeyStore loads every ES256 signing key found in dir. If dir does not
// exist it is created. If no keys are present a new one is generated and
// persisted, so the returned KeyStore is always ready for signing.
//
// Each key is stored as a PEM-encoded PKCS#8 file named
// "signing-<kid>.pem". When multiple keys are present the lexicographically
// largest kid is chosen as the active signer; the others remain published
// in the JWKS so RPs can still verify tokens issued before rotation.
func NewKeyStore(dir string, logger *slog.Logger) (*KeyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("oidc: ensure keys dir: %w", err)
	}

	keys, err := loadKeysFromDir(dir)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		generated, err := generateAndPersistKey(dir)
		if err != nil {
			return nil, err
		}
		logger.Info("generated initial signing key", "kid", generated.kid, "dir", dir)
		keys = append(keys, generated)
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].kid < keys[j].kid })
	active := keys[len(keys)-1]
	logger.Info("signing keys loaded", "count", len(keys), "active_kid", active.kid)

	return &KeyStore{keys: keys, activeKID: active.kid}, nil
}

// Active returns the kid and private key currently used to sign new tokens.
func (s *KeyStore) Active() (string, *ecdsa.PrivateKey, error) {
	if s.activeKID == "" || len(s.keys) == 0 {
		return "", nil, ErrNoActiveKey
	}

	for _, k := range s.keys {
		if k.kid == s.activeKID {
			return k.kid, k.priv, nil
		}
	}

	return "", nil, ErrNoActiveKey
}

// PublicKeyByKID returns the public key matching kid, or ErrUnknownKID if
// no loaded key matches. Used by token verifiers to resolve the signing
// key referenced in a JWS header.
func (s *KeyStore) PublicKeyByKID(kid string) (*ecdsa.PublicKey, error) {
	for _, k := range s.keys {
		if k.kid == kid {
			return &k.priv.PublicKey, nil
		}
	}
	return nil, ErrUnknownKID
}

// PublicJWKS returns the JWKS document for the /.well-known/jwks.json
// endpoint. Every currently held key is exposed as a public JWK so RPs can
// verify both freshly minted tokens and tokens still in flight from before
// the most recent rotation.
func (s *KeyStore) PublicJWKS() jose.JSONWebKeySet {
	out := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(s.keys))}

	for _, k := range s.keys {
		out.Keys = append(out.Keys, jose.JSONWebKey{
			Key:       k.priv.Public(),
			KeyID:     k.kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		})
	}

	return out
}

func loadKeysFromDir(dir string) ([]signingKey, error) {
	matches, err := filepath.Glob(filepath.Join(dir, signingKeyFilePrefix+"*.pem"))
	if err != nil {
		return nil, fmt.Errorf("oidc: scan keys dir: %w", err)
	}

	out := make([]signingKey, 0, len(matches))
	for _, path := range matches {
		key, err := loadKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("oidc: load %s: %w", filepath.Base(path), err)
		}
		out = append(out, key)
	}

	return out, nil
}

func loadKeyFile(path string) (signingKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return signingKey{}, err
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return signingKey{}, errors.New("no PEM block found")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return signingKey{}, fmt.Errorf("parse pkcs8: %w", err)
	}

	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return signingKey{}, fmt.Errorf("unexpected key type %T, want *ecdsa.PrivateKey", parsed)
	}

	if priv.Curve != elliptic.P256() {
		return signingKey{}, fmt.Errorf("unexpected curve %s, want P-256", priv.Curve.Params().Name)
	}

	return signingKey{kid: kidFor(&priv.PublicKey), priv: priv}, nil
}

func generateAndPersistKey(dir string) (signingKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return signingKey{}, fmt.Errorf("oidc: generate ecdsa key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return signingKey{}, fmt.Errorf("oidc: marshal pkcs8: %w", err)
	}

	kid := kidFor(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, signingKeyFilePrefix+kid+".pem")

	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return signingKey{}, fmt.Errorf("oidc: persist signing key: %w", err)
	}

	return signingKey{kid: kid, priv: priv}, nil
}

// kidFor derives the JWK key ID for a public key as the first 16 bytes of
// SHA-256 over its DER (SubjectPublicKeyInfo) encoding, hex-encoded. The
// truncation gives a 32-char kid that is stable across restarts and small
// enough to read at a glance in logs.
func kidFor(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// MarshalPKIXPublicKey only fails for unsupported key types; we
		// already constrain the input to *ecdsa.PublicKey, so this branch
		// is unreachable in practice. Fall back to a placeholder so an
		// unexpected failure is still observable rather than panicking.
		return "unknown"
	}

	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:16])
}
