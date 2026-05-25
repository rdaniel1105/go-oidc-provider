package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
)

// --- fakes ---

type fakeClientLookup struct {
	clients map[string]*domain.Client
}

func (f *fakeClientLookup) GetByClientID(_ context.Context, id string) (*domain.Client, error) {
	c, ok := f.clients[id]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	return c, nil
}

type fakeOPUserLookup struct {
	byPasskeyID map[uuid.UUID]*domain.OPUser
}

func (f *fakeOPUserLookup) GetByPasskeyUserID(_ context.Context, id uuid.UUID) (*domain.OPUser, error) {
	u, ok := f.byPasskeyID[id]
	if !ok {
		return nil, domain.ErrOPUserNotFound
	}
	return u, nil
}

type fakeAuthSessionStore struct {
	mu       sync.Mutex
	sessions map[string]domain.AuthSession
}

func newFakeAuthSessionStore() *fakeAuthSessionStore {
	return &fakeAuthSessionStore{sessions: map[string]domain.AuthSession{}}
}

func (f *fakeAuthSessionStore) Issue(_ context.Context, s domain.AuthSession) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.NewString()
	f.sessions[id] = s
	return id, nil
}

func (f *fakeAuthSessionStore) Consume(_ context.Context, id string) (domain.AuthSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return domain.AuthSession{}, domain.ErrAuthSessionNotFound
	}
	delete(f.sessions, id)
	return s, nil
}

type fakeAuthCodeIssuer struct {
	mu     sync.Mutex
	issued []domain.AuthCode
	next   string
	err    error
}

func (f *fakeAuthCodeIssuer) Issue(_ context.Context, code domain.AuthCode) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.issued = append(f.issued, code)
	if f.next == "" {
		return "code-" + uuid.NewString(), nil
	}
	return f.next, nil
}

type fakeLoginPasskey struct {
	beginResp     passkey.BeginLoginResponse
	beginErr      error
	completeResp  passkey.CompleteLoginResponse
	completeErr   error
	beginCalls    int
	completeCalls []passkey.CompleteLoginRequest
}

func (f *fakeLoginPasskey) BeginLogin(_ context.Context) (passkey.BeginLoginResponse, error) {
	f.beginCalls++
	return f.beginResp, f.beginErr
}

func (f *fakeLoginPasskey) CompleteLogin(_ context.Context, req passkey.CompleteLoginRequest) (passkey.CompleteLoginResponse, error) {
	f.completeCalls = append(f.completeCalls, req)
	return f.completeResp, f.completeErr
}

// --- harness ---

type authHarness struct {
	clients   *fakeClientLookup
	users     *fakeOPUserLookup
	sessions  *fakeAuthSessionStore
	authCodes *fakeAuthCodeIssuer
	passkey   *fakeLoginPasskey
	handler   *AuthorizeHandler
}

func newAuthHarness(t *testing.T) *authHarness {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clients := &fakeClientLookup{clients: map[string]*domain.Client{}}
	users := &fakeOPUserLookup{byPasskeyID: map[uuid.UUID]*domain.OPUser{}}
	sessions := newFakeAuthSessionStore()
	codes := &fakeAuthCodeIssuer{}
	p := &fakeLoginPasskey{}

	return &authHarness{
		clients:   clients,
		users:     users,
		sessions:  sessions,
		authCodes: codes,
		passkey:   p,
		handler:   NewAuthorizeHandler(clients, users, sessions, codes, p, logger),
	}
}

func validClient() *domain.Client {
	return &domain.Client{
		ID:                      uuid.New(),
		ClientID:                "demo-rp",
		RedirectURIs:            []string{"http://op.local:8082/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}
}

func authorizeURL(extra map[string]string) string {
	q := url.Values{}
	q.Set("client_id", "demo-rp")
	q.Set("redirect_uri", "http://op.local:8082/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile")
	q.Set("state", "rp-state-xyz")
	q.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	q.Set("code_challenge_method", "S256")
	q.Set("nonce", "n-0S6_WzA2Mj")
	for k, v := range extra {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return "/oidc/authorize?" + q.Encode()
}

// --- Authorize ---

func TestAuthorize_RendersLoginPage(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	h.clients.clients["demo-rp"] = validClient()

	req := httptest.NewRequest(http.MethodGet, authorizeURL(nil), nil)
	rr := httptest.NewRecorder()
	h.handler.Authorize(rr, req)

	c.Equal(http.StatusOK, rr.Code)
	c.Contains(rr.Header().Get("Content-Type"), "text/html")
	c.Equal("no-store", rr.Header().Get("Cache-Control"))
	body := rr.Body.String()
	c.Contains(body, "demo-rp")
	c.Contains(body, "/oidc/authorize/login/begin")
	c.Contains(body, "/oidc/authorize/login/complete")

	c.Len(h.sessions.sessions, 1, "an auth_session must have been issued")
}

func TestAuthorize_MissingClientID(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)

	req := httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{"client_id": ""}), nil)
	rr := httptest.NewRecorder()
	h.handler.Authorize(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Contains(rr.Body.String(), "client_id")
}

func TestAuthorize_UnknownClientID(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)

	req := httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{"client_id": "ghost"}), nil)
	rr := httptest.NewRecorder()
	h.handler.Authorize(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code)
	c.Contains(rr.Body.String(), "not registered")
}

func TestAuthorize_UnregisteredRedirectURI_RendersErrorPage(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	h.clients.clients["demo-rp"] = validClient()

	req := httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"redirect_uri": "https://evil.example.com/callback",
	}), nil)
	rr := httptest.NewRecorder()
	h.handler.Authorize(rr, req)

	c.Equal(http.StatusBadRequest, rr.Code, "must not redirect to an unregistered URI")
	c.NotEqual("", rr.Body.String())
}

func TestAuthorize_InvalidScope_RedirectsToRP(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	h.clients.clients["demo-rp"] = validClient()

	req := httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"scope": "openid payment",
	}), nil)
	rr := httptest.NewRecorder()
	h.handler.Authorize(rr, req)

	c.Equal(http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	c.Contains(loc, "error=invalid_scope")
	c.Contains(loc, "state=rp-state-xyz")
	c.True(strings.HasPrefix(loc, "http://op.local:8082/callback?"))
}

// --- LoginBegin ---

func TestLoginBegin_HappyPath(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	h.passkey.beginResp = passkey.BeginLoginResponse{
		Options:   json.RawMessage(`{"challenge":"abc"}`),
		SessionID: "pk-sess-1",
	}

	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize/login/begin",
		bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	h.handler.LoginBegin(rr, req)

	c.Equal(http.StatusOK, rr.Code)
	var resp loginBeginResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("pk-sess-1", resp.SessionID)
	c.JSONEq(`{"challenge":"abc"}`, string(resp.Options))
}

func TestLoginBegin_PasskeyUnavailable(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	h.passkey.beginErr = passkey.ErrServiceUnavailable

	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize/login/begin",
		bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	h.handler.LoginBegin(rr, req)

	c.Equal(http.StatusBadGateway, rr.Code)
	c.Equal("service_unavailable", decodeErrorCode(t, rr))
}

// --- LoginComplete ---

func seedSession(t *testing.T, h *authHarness) string {
	t.Helper()
	id, err := h.sessions.Issue(context.Background(), domain.AuthSession{
		ClientID:            "demo-rp",
		RedirectURI:         "http://op.local:8082/callback",
		Scope:               []string{"openid", "profile"},
		State:               "rp-state-xyz",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
	})
	require.NoError(t, err)
	return id
}

func postLoginComplete(t *testing.T, h *authHarness, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize/login/complete", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handler.LoginComplete(rr, req)
	return rr
}

func TestLoginComplete_HappyPath_BuildsRedirectAndMintsCode(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)

	authSessionID := seedSession(t, h)

	passkeyUserID := uuid.New()
	opUser := &domain.OPUser{
		ID:            uuid.New(),
		Email:         "alice@example.com",
		DisplayName:   "Alice",
		PasskeyUserID: passkeyUserID,
	}
	h.users.byPasskeyID[passkeyUserID] = opUser

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID:      passkeyUserID.String(),
		Username:    opUser.ID.String(),
		DisplayName: "Alice",
	}
	h.authCodes.next = "code-deadbeef"

	rr := postLoginComplete(t, h, map[string]any{
		"auth_session_id":    authSessionID,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusOK, rr.Code)

	var resp loginCompleteResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	u, err := url.Parse(resp.RedirectURL)
	c.NoError(err)
	c.Equal("op.local:8082", u.Host)
	c.Equal("/callback", u.Path)
	c.Equal("code-deadbeef", u.Query().Get("code"))
	c.Equal("rp-state-xyz", u.Query().Get("state"))

	c.Len(h.authCodes.issued, 1)
	issued := h.authCodes.issued[0]
	c.Equal("demo-rp", issued.ClientID)
	c.Equal(opUser.ID, issued.OPUserID)
	c.Equal("urn:passkey", issued.ACR)
	c.Equal([]string{"webauthn", "user"}, issued.AMR)
	c.Equal("n-0S6_WzA2Mj", issued.Nonce)

	_, err = h.sessions.Consume(context.Background(), authSessionID)
	c.ErrorIs(err, domain.ErrAuthSessionNotFound, "auth session must be single-use")
}

func TestLoginComplete_MissingFields(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	authSessionID := seedSession(t, h)

	cases := []map[string]any{
		{"passkey_session_id": "p", "credential": json.RawMessage(`{}`)},
		{"auth_session_id": authSessionID, "credential": json.RawMessage(`{}`)},
		{"auth_session_id": authSessionID, "passkey_session_id": "p"},
	}

	for i, body := range cases {
		rr := postLoginComplete(t, h, body)
		c.Equalf(http.StatusBadRequest, rr.Code, "case %d", i)
		c.Equalf("invalid_request", decodeErrorCode(t, rr), "case %d", i)
	}
}

func TestLoginComplete_UnknownAuthSession(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)

	rr := postLoginComplete(t, h, map[string]any{
		"auth_session_id":    "ghost",
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeErrorCode(t, rr))
}

func TestLoginComplete_PasskeyServiceRejects(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	authSessionID := seedSession(t, h)
	h.passkey.completeErr = &passkey.ErrService{Status: http.StatusBadRequest, Code: "invalid_request"}

	rr := postLoginComplete(t, h, map[string]any{
		"auth_session_id":    authSessionID,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestLoginComplete_OPUserNotLinked(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	authSessionID := seedSession(t, h)

	h.passkey.completeResp = passkey.CompleteLoginResponse{UserID: uuid.NewString()}
	// No entry in h.users.byPasskeyID

	rr := postLoginComplete(t, h, map[string]any{
		"auth_session_id":    authSessionID,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusForbidden, rr.Code)
	c.Equal("user_unknown", decodeErrorCode(t, rr))
}

func TestLoginComplete_PasskeyReturnsInvalidUserID(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	authSessionID := seedSession(t, h)
	h.passkey.completeResp = passkey.CompleteLoginResponse{UserID: "not-a-uuid"}

	rr := postLoginComplete(t, h, map[string]any{
		"auth_session_id":    authSessionID,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusBadGateway, rr.Code)
	c.Equal("service_unavailable", decodeErrorCode(t, rr))
}

// --- helpers + sanity ---

func TestSplitSpaceList(t *testing.T) {
	c := require.New(t)
	c.Nil(splitSpaceList(""))
	c.Equal([]string{"openid"}, splitSpaceList("openid"))
	c.Equal([]string{"openid", "profile"}, splitSpaceList("openid profile"))
	c.Equal([]string{"openid", "profile"}, splitSpaceList("  openid   profile  "))
}

func TestBuildCodeRedirect(t *testing.T) {
	c := require.New(t)
	got := buildCodeRedirect("http://op.local:8082/callback", "abc", "state-1")
	u, err := url.Parse(got)
	c.NoError(err)
	c.Equal("abc", u.Query().Get("code"))
	c.Equal("state-1", u.Query().Get("state"))

	noState := buildCodeRedirect("http://op.local:8082/callback", "abc", "")
	u2, err := url.Parse(noState)
	c.NoError(err)
	c.Empty(u2.Query().Get("state"))
}

func TestNowUTC(t *testing.T) {
	require.NotZero(t, nowUTC())
}

// Sanity that the concrete passkey client implements the login interface
// the handler depends on.
var _ passkeyLoginClient = (*passkey.Client)(nil)

// Sanity-only: confirm a transport-level error from the passkey service
// maps to 502 in LoginBegin as well.
func TestLoginBegin_TransportErrorMapsToBadGateway(t *testing.T) {
	c := require.New(t)
	h := newAuthHarness(t)
	h.passkey.beginErr = wrapTransport(errors.New("dial tcp: connection refused"))

	req := httptest.NewRequest(http.MethodPost, "/oidc/authorize/login/begin",
		bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	h.handler.LoginBegin(rr, req)

	c.Equal(http.StatusBadGateway, rr.Code)
	c.Equal("service_unavailable", decodeErrorCode(t, rr))
}

// Keep an unused import quiet — `io` is used implicitly by httptest.
var _ = io.Discard
