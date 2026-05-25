package handler

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

type publicKeyOnly struct {
	kid string
	pub *ecdsa.PublicKey
}

func (r *publicKeyOnly) PublicKeyByKID(kid string) (*ecdsa.PublicKey, error) {
	if kid != r.kid {
		return nil, oidc.ErrUnknownKID
	}
	return r.pub, nil
}

func newUserInfoHarness(t *testing.T, scope []string, user *domain.OPUser) (*UserInfoHandler, string) {
	t.Helper()

	dir := t.TempDir()
	store, err := oidc.NewKeyStore(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	kid, priv, err := store.Active()
	require.NoError(t, err)

	now := time.Now().UTC()
	access, err := oidc.MintAccessToken(oidc.AccessTokenInput{
		Issuer:    "http://op.local:8081",
		SubjectID: user.ID.String(),
		ClientID:  "demo-rp",
		IssuedAt:  now,
		Expiry:    now.Add(time.Hour),
		Scope:     scope,
	}, priv, kid)
	require.NoError(t, err)

	users := &fakeUsersByID{byID: map[uuid.UUID]*domain.OPUser{user.ID: user}}
	resolver := &publicKeyOnly{kid: kid, pub: &priv.PublicKey}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return NewUserInfoHandler(resolver, users, "http://op.local:8081", logger), access
}

func sampleUser() *domain.OPUser {
	phone := "+573001234567"
	return &domain.OPUser{
		ID:            uuid.New(),
		Email:         "alice@example.com",
		DisplayName:   "Alice",
		PhoneE164:     &phone,
		PasskeyUserID: uuid.New(),
	}
}

func getWithBearer(t *testing.T, h *UserInfoHandler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.UserInfo(rr, req)
	return rr
}

func TestUserInfo_OpenIDOnly_OnlyEmitsSub(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	h, token := newUserInfoHarness(t, []string{"openid"}, user)

	rr := getWithBearer(t, h, token)
	c.Equal(http.StatusOK, rr.Code)

	var resp userInfoResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal(user.ID.String(), resp.Sub)
	c.Empty(resp.Email)
	c.Nil(resp.EmailVerified)
	c.Empty(resp.Name)
	c.Empty(resp.PhoneNumber)
}

func TestUserInfo_EmailScope(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	h, token := newUserInfoHarness(t, []string{"openid", "email"}, user)

	rr := getWithBearer(t, h, token)
	c.Equal(http.StatusOK, rr.Code)

	var resp userInfoResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("alice@example.com", resp.Email)
	c.NotNil(resp.EmailVerified)
	c.True(*resp.EmailVerified)
	c.Empty(resp.Name)
}

func TestUserInfo_ProfileScope(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	h, token := newUserInfoHarness(t, []string{"openid", "profile"}, user)

	rr := getWithBearer(t, h, token)
	c.Equal(http.StatusOK, rr.Code)

	var resp userInfoResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("Alice", resp.Name)
	c.Empty(resp.Email)
}

func TestUserInfo_PhoneScope(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	h, token := newUserInfoHarness(t, []string{"openid", "phone"}, user)

	rr := getWithBearer(t, h, token)
	c.Equal(http.StatusOK, rr.Code)

	var resp userInfoResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("+573001234567", resp.PhoneNumber)
}

func TestUserInfo_MissingAuthorization(t *testing.T) {
	c := require.New(t)
	h, _ := newUserInfoHarness(t, []string{"openid"}, sampleUser())

	rr := getWithBearer(t, h, "")
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Contains(rr.Header().Get("WWW-Authenticate"), "Bearer")
	c.Equal("invalid_token", decodeErrorCode(t, rr))
}

func TestUserInfo_MalformedBearer(t *testing.T) {
	c := require.New(t)
	h, _ := newUserInfoHarness(t, []string{"openid"}, sampleUser())

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Basic abc")
	rr := httptest.NewRecorder()
	h.UserInfo(rr, req)

	c.Equal(http.StatusUnauthorized, rr.Code)
}

func TestUserInfo_TamperedToken(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	h, token := newUserInfoHarness(t, []string{"openid"}, user)

	// Flip a character in the JWT signature segment.
	parts := strings.Split(token, ".")
	c.Len(parts, 3)
	parts[2] = "AAAA" + parts[2][4:]
	tampered := strings.Join(parts, ".")

	rr := getWithBearer(t, h, tampered)
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Contains(rr.Header().Get("WWW-Authenticate"), "invalid_token")
}

func TestUserInfo_ExpiredToken(t *testing.T) {
	c := require.New(t)
	user := sampleUser()

	dir := t.TempDir()
	store, err := oidc.NewKeyStore(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.NoError(err)
	kid, priv, err := store.Active()
	c.NoError(err)

	// Mint a token that has already expired.
	past := time.Now().Add(-2 * time.Hour).UTC()
	tok, err := oidc.MintAccessToken(oidc.AccessTokenInput{
		Issuer:    "http://op.local:8081",
		SubjectID: user.ID.String(),
		ClientID:  "demo-rp",
		IssuedAt:  past,
		Expiry:    past.Add(time.Hour),
		Scope:     []string{"openid"},
	}, priv, kid)
	c.NoError(err)

	users := &fakeUsersByID{byID: map[uuid.UUID]*domain.OPUser{user.ID: user}}
	h := NewUserInfoHandler(&publicKeyOnly{kid: kid, pub: &priv.PublicKey},
		users, "http://op.local:8081", slog.New(slog.NewTextHandler(io.Discard, nil)))

	rr := getWithBearer(t, h, tok)
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Contains(rr.Header().Get("WWW-Authenticate"), "expired")
}

func TestUserInfo_UserDeleted(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	h, token := newUserInfoHarness(t, []string{"openid"}, user)

	// Remove the user behind the handler's back via the unexposed field.
	// We have to reconstruct: the harness stored a fake users map, but it
	// is not reachable from h. Build a separate handler with an empty store.

	dir := t.TempDir()
	store, err := oidc.NewKeyStore(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.NoError(err)
	kid, priv, err := store.Active()
	c.NoError(err)

	now := time.Now().UTC()
	freshTok, err := oidc.MintAccessToken(oidc.AccessTokenInput{
		Issuer:    "http://op.local:8081",
		SubjectID: user.ID.String(),
		ClientID:  "demo-rp",
		IssuedAt:  now,
		Expiry:    now.Add(time.Hour),
		Scope:     []string{"openid"},
	}, priv, kid)
	c.NoError(err)

	empty := &fakeUsersByID{byID: map[uuid.UUID]*domain.OPUser{}}
	h2 := NewUserInfoHandler(&publicKeyOnly{kid: kid, pub: &priv.PublicKey}, empty,
		"http://op.local:8081", slog.New(slog.NewTextHandler(io.Discard, nil)))

	rr := getWithBearer(t, h2, freshTok)
	c.Equal(http.StatusUnauthorized, rr.Code)
	_ = h // not used; keeps the import set honest
	_ = token
}

func TestExtractBearerToken(t *testing.T) {
	c := require.New(t)

	mk := func(h string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		return r
	}

	tok, ok := extractBearerToken(mk("Bearer abc"))
	c.True(ok)
	c.Equal("abc", tok)

	_, ok = extractBearerToken(mk(""))
	c.False(ok)

	_, ok = extractBearerToken(mk("Basic abc"))
	c.False(ok)

	_, ok = extractBearerToken(mk("Bearer "))
	c.False(ok)

	// Case-sensitive scheme per RFC 6750.
	_, ok = extractBearerToken(mk("bearer abc"))
	c.False(ok)
}

