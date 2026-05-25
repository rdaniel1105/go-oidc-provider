package handler

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

// --- fakes ---

type fakeAuthCodeConsumer struct {
	mu     sync.Mutex
	stored map[string]*domain.AuthCode
}

func newFakeAuthCodeConsumer() *fakeAuthCodeConsumer {
	return &fakeAuthCodeConsumer{stored: map[string]*domain.AuthCode{}}
}

func (f *fakeAuthCodeConsumer) Consume(_ context.Context, code string) (*domain.AuthCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	got, ok := f.stored[code]
	if !ok {
		return nil, domain.ErrAuthCodeNotFound
	}
	delete(f.stored, code)
	return got, nil
}

type fakeUsersByID struct {
	mu   sync.Mutex
	byID map[uuid.UUID]*domain.OPUser
}

func (f *fakeUsersByID) GetByID(_ context.Context, id uuid.UUID) (*domain.OPUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrOPUserNotFound
	}
	return u, nil
}

type fakeRefreshCreator struct {
	mu       sync.Mutex
	created  []*domain.RefreshToken
}

func (f *fakeRefreshCreator) Create(_ context.Context, t *domain.RefreshToken) (*domain.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.ID = uuid.New()
	t.IssuedAt = time.Now().UTC()
	f.created = append(f.created, t)
	return t, nil
}

type fakeKeySource struct {
	kid  string
	priv *ecdsa.PrivateKey
}

func (f *fakeKeySource) Active() (string, *ecdsa.PrivateKey, error) {
	return f.kid, f.priv, nil
}

// --- harness ---

type tokenHarness struct {
	clients   *fakeClients
	authCodes *fakeAuthCodeConsumer
	users     *fakeUsersByID
	refresh   *fakeRefreshCreator
	keys      *fakeKeySource
	handler   *TokenHandler
}

func newTokenHarness(t *testing.T) *tokenHarness {
	t.Helper()

	dir := t.TempDir()
	store, err := oidc.NewKeyStore(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	kid, priv, err := store.Active()
	require.NoError(t, err)

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}
	authCodes := newFakeAuthCodeConsumer()
	users := &fakeUsersByID{byID: map[uuid.UUID]*domain.OPUser{}}
	refresh := &fakeRefreshCreator{}
	keys := &fakeKeySource{kid: kid, priv: priv}

	h := NewTokenHandler(TokenHandlerDeps{
		Clients:    clients,
		AuthCodes:  authCodes,
		Users:      users,
		Refresh:    refresh,
		Keys:       keys,
		Issuer:     "http://op.local:8081",
		AccessTTL:  time.Hour,
		RefreshTTL: 720 * time.Hour,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	return &tokenHarness{
		clients:   clients,
		authCodes: authCodes,
		users:     users,
		refresh:   refresh,
		keys:      keys,
		handler:   h,
	}
}

// fakeClients lives in oidc tests; redefine a local one to avoid coupling
// the handler tests to package-internal types of another package.
type fakeClients struct {
	byClientID map[string]*domain.Client
}

func (f *fakeClients) GetByClientID(_ context.Context, id string) (*domain.Client, error) {
	c, ok := f.byClientID[id]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	return c, nil
}

func bcryptHash(t *testing.T, secret string) *string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)
	s := string(h)
	return &s
}

func postForm(t *testing.T, h *TokenHandler, form url.Values, basicAuth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	return rr
}

func basic(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func seedHappyState(t *testing.T, h *tokenHarness) (code, verifier string, user *domain.OPUser) {
	t.Helper()

	h.clients.byClientID["demo-rp"] = &domain.Client{
		ID:                      uuid.New(),
		ClientID:                "demo-rp",
		ClientSecretHash:        bcryptHash(t, "super-secret"),
		RedirectURIs:            []string{"http://op.local:8082/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	user = &domain.OPUser{
		ID:            uuid.New(),
		Email:         "alice@example.com",
		DisplayName:   "Alice",
		PasskeyUserID: uuid.New(),
	}
	h.users.byID[user.ID] = user

	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	code = "stored-code"
	h.authCodes.stored[code] = &domain.AuthCode{
		ClientID:            "demo-rp",
		OPUserID:            user.ID,
		RedirectURI:         "http://op.local:8082/callback",
		Scope:               []string{"openid", "profile", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
		ACR:                 "urn:passkey",
		AMR:                 []string{"webauthn", "user"},
		IssuedAt:            time.Now().UTC().Add(-time.Minute),
	}

	return code, verifier, user
}

// --- Tests ---

func TestToken_AuthCode_HappyPath(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	code, verifier, user := seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", verifier)

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp tokenResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("Bearer", resp.TokenType)
	c.Equal(3600, resp.ExpiresIn)
	c.Equal("openid profile email", resp.Scope)
	c.NotEmpty(resp.AccessToken)
	c.NotEmpty(resp.IDToken)
	c.NotEmpty(resp.RefreshToken)

	// ID token verifies and carries the expected claims.
	parsed, err := jwt.ParseSigned(resp.IDToken, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)
	var idClaims oidc.IDTokenClaims
	c.NoError(parsed.Claims(&h.keys.priv.PublicKey, &idClaims))
	c.Equal("http://op.local:8081", idClaims.Issuer)
	c.Equal("demo-rp", idClaims.Audience)
	c.Equal(user.ID.String(), idClaims.Subject)
	c.Equal("urn:passkey", idClaims.ACR)
	c.Equal([]string{"webauthn", "user"}, idClaims.AMR)
	c.Equal("n-0S6_WzA2Mj", idClaims.Nonce)
	c.Equal("alice@example.com", idClaims.Email)
	c.Equal("Alice", idClaims.Name)

	// Access token verifies and carries the expected claims.
	parsedAT, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)
	var atClaims oidc.AccessTokenClaims
	c.NoError(parsedAT.Claims(&h.keys.priv.PublicKey, &atClaims))
	c.Equal("http://op.local:8081", atClaims.Issuer)
	c.Equal("http://op.local:8081", atClaims.Audience)
	c.Equal("demo-rp", atClaims.ClientID)
	c.Equal("openid profile email", atClaims.Scope)

	// Refresh token persisted with a hash, not the raw value.
	c.Len(h.refresh.created, 1)
	c.NotEqual(resp.RefreshToken, h.refresh.created[0].TokenHash)
	c.Equal(oidc.HashRefreshToken(resp.RefreshToken), h.refresh.created[0].TokenHash)
	c.Equal("demo-rp", h.refresh.created[0].ClientID)
	c.Equal(user.ID, h.refresh.created[0].OPUserID)

	// Code is single-use: consumed.
	_, ok := h.authCodes.stored[code]
	c.False(ok)
}

func TestToken_InvalidClientSecret(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	_, _, _ = seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "stored-code")
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	rr := postForm(t, h.handler, form, basic("demo-rp", "WRONG"))
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("invalid_client", decodeErrorCode(t, rr))
}

func TestToken_UnsupportedGrant(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	_, _, _ = seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("unsupported_grant_type", decodeErrorCode(t, rr))
}

func TestToken_AuthCode_MissingFields(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	_, _, _ = seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	// no code / redirect_uri / verifier

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestToken_AuthCode_UnknownCode(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	_, _, _ = seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "ghost")
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_AuthCode_BoundToDifferentClient(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	code, verifier, _ := seedHappyState(t, h)

	// Add a second client and authenticate as that one — its
	// credentials are valid but the code belongs to demo-rp.
	h.clients.byClientID["other-rp"] = &domain.Client{
		ClientID:                "other-rp",
		ClientSecretHash:        bcryptHash(t, "other-secret"),
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", verifier)

	rr := postForm(t, h.handler, form, basic("other-rp", "other-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_AuthCode_RedirectURIMismatch(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	code, verifier, _ := seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://op.local:8082/different")
	form.Set("code_verifier", verifier)

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_AuthCode_PKCEMismatch(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	code, _, _ := seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", "wrong-verifier")

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_AuthCode_UserDeleted(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	code, verifier, user := seedHappyState(t, h)

	delete(h.users.byID, user.ID)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", verifier)

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}
