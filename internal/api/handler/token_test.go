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

type fakeRefreshStore struct {
	mu              sync.Mutex
	created         []*domain.RefreshToken
	byHash          map[string]*domain.RefreshToken
	revokedFamilies []uuid.UUID
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{byHash: map[string]*domain.RefreshToken{}}
}

func (f *fakeRefreshStore) Create(_ context.Context, t *domain.RefreshToken) (*domain.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}

	if t.FamilyID == uuid.Nil {
		t.FamilyID = uuid.New()
	}

	t.IssuedAt = time.Now().UTC()
	stored := *t

	f.created = append(f.created, &stored)
	f.byHash[t.TokenHash] = &stored

	return &stored, nil
}

func (f *fakeRefreshStore) GetByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	got, ok := f.byHash[hash]
	if !ok {
		return nil, domain.ErrRefreshTokenNotFound
	}

	cp := *got

	return &cp, nil
}

func (f *fakeRefreshStore) Revoke(_ context.Context, id uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, tok := range f.byHash {
		if tok.ID == id {
			if tok.RevokedAt == nil {
				stamp := at
				tok.RevokedAt = &stamp
			}
			return nil
		}
	}

	return domain.ErrRefreshTokenNotFound
}

func (f *fakeRefreshStore) RevokeFamily(_ context.Context, familyID uuid.UUID, at time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var n int64

	for _, tok := range f.byHash {
		if tok.FamilyID == familyID && tok.RevokedAt == nil {
			stamp := at
			tok.RevokedAt = &stamp
			n++
		}
	}

	if n > 0 {
		f.revokedFamilies = append(f.revokedFamilies, familyID)
	}

	return n, nil
}

type fakeCIBARedeemer struct {
	mu      sync.Mutex
	stored  map[string]*domain.CIBARequest
	deleted []string
}

func newFakeCIBARedeemer() *fakeCIBARedeemer {
	return &fakeCIBARedeemer{stored: map[string]*domain.CIBARequest{}}
}

func (f *fakeCIBARedeemer) Get(_ context.Context, authReqID string) (*domain.CIBARequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.stored[authReqID]
	if !ok {
		return nil, domain.ErrCIBARequestNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeCIBARedeemer) Delete(_ context.Context, authReqID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.stored[authReqID]; ok {
		delete(f.stored, authReqID)
		f.deleted = append(f.deleted, authReqID)
	}
	return nil
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
	refresh   *fakeRefreshStore
	ciba      *fakeCIBARedeemer
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
	refresh := newFakeRefreshStore()
	ciba := newFakeCIBARedeemer()
	keys := &fakeKeySource{kid: kid, priv: priv}

	h := NewTokenHandler(TokenHandlerDeps{
		Clients:      clients,
		AuthCodes:    authCodes,
		Users:        users,
		Refresh:      refresh,
		CIBA:         ciba,
		Keys:         keys,
		Issuer:       "http://op.local:8081",
		AccessTTL:    time.Hour,
		RefreshTTL:   720 * time.Hour,
		PollInterval: 5,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	return &tokenHarness{
		clients:   clients,
		authCodes: authCodes,
		users:     users,
		refresh:   refresh,
		ciba:      ciba,
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

// --- Refresh grant ---

// completeAuthCodeExchange runs the auth_code grant against the harness
// and returns the parsed token response. Subsequent refresh-grant tests
// chain off the refresh_token field of this response.
func completeAuthCodeExchange(t *testing.T, h *tokenHarness) tokenResponse {
	t.Helper()
	code, verifier, _ := seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://op.local:8082/callback")
	form.Set("code_verifier", verifier)

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp tokenResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	return resp
}

func refreshForm(refreshToken string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	return form
}

func TestToken_Refresh_HappyPath_RotatesAndPreservesFamily(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	// Snapshot the original row's family + auth_time before rotation
	// consumes it.
	originalRow, err := h.refresh.GetByHash(t.Context(), oidc.HashRefreshToken(first.RefreshToken))
	c.NoError(err)
	originalFamily := originalRow.FamilyID
	originalAuth := originalRow.AuthTime

	rr := postForm(t, h.handler, refreshForm(first.RefreshToken), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var second tokenResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&second))
	c.NotEqual(first.RefreshToken, second.RefreshToken, "rotation must mint a fresh refresh token")
	c.NotEqual(first.AccessToken, second.AccessToken)
	c.Equal("openid profile email", second.Scope)

	// New row carries the same family + auth_time as the parent.
	newRow, err := h.refresh.GetByHash(t.Context(), oidc.HashRefreshToken(second.RefreshToken))
	c.NoError(err)
	c.Equal(originalFamily, newRow.FamilyID, "family must persist across rotation")
	c.WithinDuration(originalAuth, newRow.AuthTime, time.Second)
	c.Nil(newRow.RevokedAt)

	// Old row is now revoked.
	oldRow, err := h.refresh.GetByHash(t.Context(), oidc.HashRefreshToken(first.RefreshToken))
	c.NoError(err)
	c.NotNil(oldRow.RevokedAt, "the presented token must be revoked after rotation")

	// ID token carries auth_time from the original chain, not the
	// rotation moment.
	parsed, err := jwt.ParseSigned(second.IDToken, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)
	var claims oidc.IDTokenClaims
	c.NoError(parsed.Claims(&h.keys.priv.PublicKey, &claims))
	c.Equal(originalAuth.Unix(), claims.AuthTime, "refreshed ID token must keep the original auth_time")
	c.Empty(claims.Nonce, "refreshed ID tokens omit nonce")
}

func TestToken_Refresh_ReplayRevokesFamily(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	originalRow, err := h.refresh.GetByHash(t.Context(), oidc.HashRefreshToken(first.RefreshToken))
	c.NoError(err)
	family := originalRow.FamilyID

	// First rotation succeeds — first refresh is now revoked.
	rr := postForm(t, h.handler, refreshForm(first.RefreshToken), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code)

	var second tokenResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&second))

	// Replay the first refresh — must be rejected AND the new (live)
	// descendant must be taken down by the family revoke.
	rr = postForm(t, h.handler, refreshForm(first.RefreshToken), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))

	c.Contains(h.refresh.revokedFamilies, family, "replay must trigger a RevokeFamily call")

	// The freshly rotated token is now also revoked.
	rotatedRow, err := h.refresh.GetByHash(t.Context(), oidc.HashRefreshToken(second.RefreshToken))
	c.NoError(err)
	c.NotNil(rotatedRow.RevokedAt, "descendants of the family must be revoked too")

	// And a follow-up exchange of that rotated token fails.
	rr = postForm(t, h.handler, refreshForm(second.RefreshToken), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_Refresh_UnknownToken(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	_, _, _ = seedHappyState(t, h)

	rr := postForm(t, h.handler, refreshForm("never-issued"), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_Refresh_MissingToken(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	_, _, _ = seedHappyState(t, h)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestToken_Refresh_ClientMismatchRevokesFamily(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	originalRow, err := h.refresh.GetByHash(t.Context(), oidc.HashRefreshToken(first.RefreshToken))
	c.NoError(err)
	family := originalRow.FamilyID

	// Register a second client and present the first client's token.
	h.clients.byClientID["other-rp"] = &domain.Client{
		ClientID:                "other-rp",
		ClientSecretHash:        bcryptHash(t, "other-secret"),
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	rr := postForm(t, h.handler, refreshForm(first.RefreshToken), basic("other-rp", "other-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
	c.Contains(h.refresh.revokedFamilies, family,
		"a client mismatch is treated as a theft signal — revoke the family")
}

func TestToken_Refresh_ScopeNarrowing_Works(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	form := refreshForm(first.RefreshToken)
	form.Set("scope", "openid")

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp tokenResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("openid", resp.Scope, "narrowed scope must reflect in the response")
}

func TestToken_Refresh_ScopeWideningRejected(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	form := refreshForm(first.RefreshToken)
	form.Set("scope", "openid payment")

	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_scope", decodeErrorCode(t, rr))
}

func TestToken_Refresh_ExpiredToken(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	// Forcibly age the row.
	hash := oidc.HashRefreshToken(first.RefreshToken)
	h.refresh.byHash[hash].ExpiresAt = time.Now().Add(-time.Minute)

	rr := postForm(t, h.handler, refreshForm(first.RefreshToken), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestToken_Refresh_UserDeleted(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	first := completeAuthCodeExchange(t, h)

	hash := oidc.HashRefreshToken(first.RefreshToken)
	uid := h.refresh.byHash[hash].OPUserID
	delete(h.users.byID, uid)

	rr := postForm(t, h.handler, refreshForm(first.RefreshToken), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}

func TestNarrowRefreshScope(t *testing.T) {
	c := require.New(t)

	got, err := narrowRefreshScope([]string{"openid", "profile"}, "")
	c.NoError(err)
	c.Equal([]string{"openid", "profile"}, got)

	got, err = narrowRefreshScope([]string{"openid", "profile"}, "openid")
	c.NoError(err)
	c.Equal([]string{"openid"}, got)

	_, err = narrowRefreshScope([]string{"openid"}, "openid payment")
	c.Error(err)
}

// --- CIBA grant ---

func seedCIBARequest(t *testing.T, h *tokenHarness, status domain.CIBAStatus) (authReqID string, user *domain.OPUser) {
	t.Helper()

	h.clients.byClientID["demo-rp"] = &domain.Client{
		ID:                      uuid.New(),
		ClientID:                "demo-rp",
		ClientSecretHash:        bcryptHash(t, "super-secret"),
		GrantTypes:              []string{oidc.CIBAGrantType},
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

	authReqID = "auth-req-ciba"
	now := time.Now().UTC()
	req := &domain.CIBARequest{
		ClientID:       "demo-rp",
		OPUserID:       user.ID,
		Scope:          []string{"openid", "profile"},
		BindingMessage: "Authorize $50",
		Status:         status,
		IssuedAt:       now.Add(-30 * time.Second),
	}
	if status == domain.CIBAStatusApproved {
		t := now
		req.ApprovedAt = &t
	} else if status == domain.CIBAStatusDenied {
		t := now
		req.DeniedAt = &t
	}
	h.ciba.stored[authReqID] = req

	return authReqID, user
}

func cibaTokenForm(authReqID string) url.Values {
	form := url.Values{}
	form.Set("grant_type", oidc.CIBAGrantType)
	form.Set("auth_req_id", authReqID)
	return form
}

func TestToken_CIBA_Pending(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	authReqID, _ := seedCIBARequest(t, h, domain.CIBAStatusPending)

	rr := postForm(t, h.handler, cibaTokenForm(authReqID), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("authorization_pending", decodeErrorCode(t, rr))

	// Pending requests are NOT deleted on poll — the next call must
	// still see them.
	_, ok := h.ciba.stored[authReqID]
	c.True(ok)
}

func TestToken_CIBA_Denied(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	authReqID, _ := seedCIBARequest(t, h, domain.CIBAStatusDenied)

	rr := postForm(t, h.handler, cibaTokenForm(authReqID), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("access_denied", decodeErrorCode(t, rr))

	// Denied requests are deleted so they cannot be polled forever.
	c.Contains(h.ciba.deleted, authReqID)
}

func TestToken_CIBA_Approved_MintsTokens(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	authReqID, user := seedCIBARequest(t, h, domain.CIBAStatusApproved)

	rr := postForm(t, h.handler, cibaTokenForm(authReqID), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp tokenResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("Bearer", resp.TokenType)
	c.Equal(3600, resp.ExpiresIn)
	c.Equal("openid profile", resp.Scope)
	c.NotEmpty(resp.AccessToken)
	c.NotEmpty(resp.IDToken)
	c.NotEmpty(resp.RefreshToken)

	// ID token carries acr/amr + auth_time from the approval moment.
	parsed, err := jwt.ParseSigned(resp.IDToken, []jose.SignatureAlgorithm{jose.ES256})
	c.NoError(err)
	var idClaims oidc.IDTokenClaims
	c.NoError(parsed.Claims(&h.keys.priv.PublicKey, &idClaims))
	c.Equal(user.ID.String(), idClaims.Subject)
	c.Equal("demo-rp", idClaims.Audience)
	c.Equal("urn:passkey", idClaims.ACR)
	c.Equal([]string{"webauthn", "user"}, idClaims.AMR)
	c.NotZero(idClaims.AuthTime)
	c.Empty(idClaims.Nonce, "CIBA does not carry a nonce")

	// Refresh token persisted.
	c.Len(h.refresh.created, 1)
	c.Equal(oidc.HashRefreshToken(resp.RefreshToken), h.refresh.created[0].TokenHash)

	// Approved request is consumed: a second poll must see expired_token.
	c.Contains(h.ciba.deleted, authReqID)
	rr2 := postForm(t, h.handler, cibaTokenForm(authReqID), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr2.Code)
	c.Equal("expired_token", decodeErrorCode(t, rr2))
}

func TestToken_CIBA_UnknownAuthReqID(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	h.clients.byClientID["demo-rp"] = &domain.Client{
		ClientID:                "demo-rp",
		ClientSecretHash:        bcryptHash(t, "super-secret"),
		GrantTypes:              []string{oidc.CIBAGrantType},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	rr := postForm(t, h.handler, cibaTokenForm("ghost"), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("expired_token", decodeErrorCode(t, rr))
}

func TestToken_CIBA_MissingAuthReqID(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	h.clients.byClientID["demo-rp"] = &domain.Client{
		ClientID:                "demo-rp",
		ClientSecretHash:        bcryptHash(t, "super-secret"),
		GrantTypes:              []string{oidc.CIBAGrantType},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	form := url.Values{}
	form.Set("grant_type", oidc.CIBAGrantType)
	rr := postForm(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestToken_CIBA_BoundToDifferentClient(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	authReqID, _ := seedCIBARequest(t, h, domain.CIBAStatusApproved)

	// Second client authenticates correctly but doesn't own the request.
	h.clients.byClientID["other-rp"] = &domain.Client{
		ClientID:                "other-rp",
		ClientSecretHash:        bcryptHash(t, "other-secret"),
		GrantTypes:              []string{oidc.CIBAGrantType},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	rr := postForm(t, h.handler, cibaTokenForm(authReqID), basic("other-rp", "other-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))

	// Request must not be deleted when the wrong client tries — the
	// rightful client must still be able to redeem it.
	_, ok := h.ciba.stored[authReqID]
	c.True(ok)
}

func TestToken_CIBA_UserDeleted(t *testing.T) {
	c := require.New(t)
	h := newTokenHarness(t)
	authReqID, user := seedCIBARequest(t, h, domain.CIBAStatusApproved)
	delete(h.users.byID, user.ID)

	rr := postForm(t, h.handler, cibaTokenForm(authReqID), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_grant", decodeErrorCode(t, rr))
}
