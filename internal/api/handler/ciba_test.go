package handler

import (
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
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/notifier"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
)

// --- fakes ---

type fakeOPUsersByEmail struct {
	mu      sync.Mutex
	byEmail map[string]*domain.OPUser
}

func (f *fakeOPUsersByEmail) GetByEmail(_ context.Context, email string) (*domain.OPUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrOPUserNotFound
	}
	return u, nil
}

type fakeCIBARequestIssuer struct {
	mu     sync.Mutex
	issued []struct {
		Req domain.CIBARequest
		TTL time.Duration
	}
	stored map[string]*domain.CIBARequest
	nextID string
	err    error
}

func newFakeCIBARequestIssuer() *fakeCIBARequestIssuer {
	return &fakeCIBARequestIssuer{stored: map[string]*domain.CIBARequest{}}
}

func (f *fakeCIBARequestIssuer) Issue(_ context.Context, req domain.CIBARequest, ttl time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.issued = append(f.issued, struct {
		Req domain.CIBARequest
		TTL time.Duration
	}{req, ttl})
	id := f.nextID
	if id == "" {
		id = uuid.NewString()
	}
	stamped := req
	stamped.Status = domain.CIBAStatusPending
	stamped.IssuedAt = time.Now().UTC()
	f.stored[id] = &stamped
	return id, nil
}

func (f *fakeCIBARequestIssuer) Get(_ context.Context, authReqID string) (*domain.CIBARequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.stored[authReqID]
	if !ok {
		return nil, domain.ErrCIBARequestNotFound
	}
	cp := *r
	return &cp, nil
}

type fakeApprovalTokens struct {
	mu     sync.Mutex
	issued []string
	bound  map[string]string // token -> authReqID
	next   string
	err    error
}

func newFakeApprovalTokens() *fakeApprovalTokens {
	return &fakeApprovalTokens{bound: map[string]string{}}
}

func (f *fakeApprovalTokens) Issue(_ context.Context, authReqID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.issued = append(f.issued, authReqID)
	token := f.next
	if token == "" {
		token = "tok-" + authReqID
	}
	f.bound[token] = authReqID
	return token, nil
}

func (f *fakeApprovalTokens) Peek(_ context.Context, token string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.bound[token]
	if !ok {
		return "", domain.ErrApprovalTokenNotFound
	}
	return id, nil
}

func (f *fakeApprovalTokens) Consume(_ context.Context, token string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.bound[token]
	if !ok {
		return "", domain.ErrApprovalTokenNotFound
	}
	delete(f.bound, token)
	return id, nil
}

// Approve flips the stored request to approved if it is currently pending.
func (f *fakeCIBARequestIssuer) Approve(_ context.Context, authReqID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.stored[authReqID]
	if !ok {
		return domain.ErrCIBARequestNotFound
	}
	if r.Status != domain.CIBAStatusPending {
		return domain.ErrCIBANotPending
	}
	r.Status = domain.CIBAStatusApproved
	stamp := at
	r.ApprovedAt = &stamp
	return nil
}

// Deny flips the stored request to denied if it is currently pending.
func (f *fakeCIBARequestIssuer) Deny(_ context.Context, authReqID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.stored[authReqID]
	if !ok {
		return domain.ErrCIBARequestNotFound
	}
	if r.Status != domain.CIBAStatusPending {
		return domain.ErrCIBANotPending
	}
	r.Status = domain.CIBAStatusDenied
	stamp := at
	r.DeniedAt = &stamp
	return nil
}

// fakeCIBACallback records callbacks the handler initiates to RP
// notification endpoints.
type fakeCIBACallback struct {
	mu    sync.Mutex
	calls []fakeCIBACallbackCall
	err   error
}

type fakeCIBACallbackCall struct {
	Endpoint                string
	ClientNotificationToken string
	AuthReqID               string
}

func (f *fakeCIBACallback) Ping(_ context.Context, endpoint, clientNotificationToken, authReqID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCIBACallbackCall{
		Endpoint:                endpoint,
		ClientNotificationToken: clientNotificationToken,
		AuthReqID:               authReqID,
	})
	return f.err
}

// fakeOPUsersByPasskeyID maps passkey-side user_id → op_user for the
// post-assertion user-match check.
type fakeOPUsersByPasskeyID struct {
	mu          sync.Mutex
	byPasskeyID map[uuid.UUID]*domain.OPUser
}

func (f *fakeOPUsersByPasskeyID) GetByPasskeyUserID(_ context.Context, id uuid.UUID) (*domain.OPUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byPasskeyID[id]
	if !ok {
		return nil, domain.ErrOPUserNotFound
	}
	return u, nil
}

type fakeNotifier struct {
	mu       sync.Mutex
	received []notifier.Notification
	err      error
}

func (f *fakeNotifier) Notify(_ context.Context, n notifier.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.received = append(f.received, n)
	return nil
}

// --- harness ---

type cibaHarness struct {
	clients        *fakeClients
	users          *fakeOPUsersByEmail
	usersByPasskey *fakeOPUsersByPasskeyID
	cibaReqs       *fakeCIBARequestIssuer
	approvalTks    *fakeApprovalTokens
	passkey        *fakeLoginPasskey
	notifier       *fakeNotifier
	callback       *fakeCIBACallback
	handler        *CIBAHandler
}

func newCIBAHarness(t *testing.T) *cibaHarness {
	t.Helper()

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}
	users := &fakeOPUsersByEmail{byEmail: map[string]*domain.OPUser{}}
	usersByPasskey := &fakeOPUsersByPasskeyID{byPasskeyID: map[uuid.UUID]*domain.OPUser{}}
	cibaReqs := newFakeCIBARequestIssuer()
	approvals := newFakeApprovalTokens()
	pk := &fakeLoginPasskey{}
	n := &fakeNotifier{}
	cb := &fakeCIBACallback{}

	return &cibaHarness{
		clients:        clients,
		users:          users,
		usersByPasskey: usersByPasskey,
		cibaReqs:       cibaReqs,
		approvalTks:    approvals,
		passkey:        pk,
		notifier:       n,
		callback:       cb,
		handler: NewCIBAHandler(CIBAHandlerDeps{
			Clients:                  clients,
			Users:                    users,
			UsersByPasskey:           usersByPasskey,
			CIBARequests:             cibaReqs,
			CIBARequestsReader:       cibaReqs,
			CIBARequestsTransitioner: cibaReqs,
			ApprovalTokens:           approvals,
			ApprovalTokensReader:     approvals,
			ApprovalTokensConsumer:   approvals,
			Passkey:                  pk,
			Notifier:                 n,
			Callback:                 cb,
			Issuer:                   "http://op.local:8081",
			DefaultTTL:               10 * time.Minute,
			PollInterval:             5,
			Logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		}),
	}
}

func seedCIBAClient(t *testing.T, h *cibaHarness) {
	t.Helper()
	h.clients.byClientID["demo-rp"] = &domain.Client{
		ID:               uuid.New(),
		ClientID:         "demo-rp",
		ClientSecretHash: bcryptHash(t, "super-secret"),
		RedirectURIs:     []string{"http://op.local:8082/callback"},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			oidc.CIBAGrantType,
		},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "payment"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}
}

func seedCIBAUser(t *testing.T, h *cibaHarness) *domain.OPUser {
	t.Helper()
	phone := "+573001234567"
	u := &domain.OPUser{
		ID:            uuid.New(),
		Email:         "alice@example.com",
		DisplayName:   "Alice",
		PhoneE164:     &phone,
		PasskeyUserID: uuid.New(),
	}
	h.users.byEmail[u.Email] = u
	return u
}

func bcAuthorizeForm() url.Values {
	form := url.Values{}
	form.Set("scope", "openid payment")
	form.Set("login_hint", "alice@example.com")
	form.Set("binding_message", "Authorize $50 to Café Acme")
	form.Set("acr_values", "urn:passkey")
	form.Set("client_notification_token", "rp-correlation-id")
	form.Set("requested_expiry", "300")
	return form
}

func postCIBA(t *testing.T, h *CIBAHandler, form url.Values, basicAuth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oidc/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth != "" {
		req.Header.Set("Authorization", basicAuth)
	}
	rr := httptest.NewRecorder()
	h.BCAuthorize(rr, req)
	return rr
}

// --- Tests ---

func TestBCAuthorize_HappyPath(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	user := seedCIBAUser(t, h)
	h.cibaReqs.nextID = "auth-req-xyz"
	h.approvalTks.next = "tok-abc"

	rr := postCIBA(t, h.handler, bcAuthorizeForm(), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp bcAuthorizeResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("auth-req-xyz", resp.AuthReqID)
	c.Equal(300, resp.ExpiresIn)
	c.Equal(5, resp.Interval)

	c.Len(h.cibaReqs.issued, 1)
	saved := h.cibaReqs.issued[0]
	c.Equal("demo-rp", saved.Req.ClientID)
	c.Equal(user.ID, saved.Req.OPUserID)
	c.Equal([]string{"openid", "payment"}, saved.Req.Scope)
	c.Equal("Authorize $50 to Café Acme", saved.Req.BindingMessage)
	c.Equal("rp-correlation-id", saved.Req.ClientNotificationToken)
	c.Equal(5*time.Minute, saved.TTL)

	c.Equal([]string{"auth-req-xyz"}, h.approvalTks.issued)

	c.Len(h.notifier.received, 1)
	delivered := h.notifier.received[0]
	c.Equal(user, delivered.User)
	c.Equal("demo-rp", delivered.ClientName)
	c.Equal("Authorize $50 to Café Acme", delivered.BindingMessage)
	c.Equal("http://op.local:8081/ciba/approve?t=tok-abc", delivered.ApprovalURL)
}

func TestBCAuthorize_InvalidClientSecret(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	rr := postCIBA(t, h.handler, bcAuthorizeForm(), basic("demo-rp", "WRONG"))
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("invalid_client", decodeErrorCode(t, rr))
	c.Empty(h.notifier.received)
}

func TestBCAuthorize_ClientNotAllowedCIBA(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)
	// Strip the CIBA grant from the registered client.
	h.clients.byClientID["demo-rp"].GrantTypes = []string{"authorization_code"}

	rr := postCIBA(t, h.handler, bcAuthorizeForm(), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("unauthorized_client", decodeErrorCode(t, rr))
}

func TestBCAuthorize_UnknownLoginHint(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)

	rr := postCIBA(t, h.handler, bcAuthorizeForm(), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("unknown_user_id", decodeErrorCode(t, rr))
	c.Empty(h.notifier.received)
}

func TestBCAuthorize_InvalidScope(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	form := bcAuthorizeForm()
	form.Set("scope", "openid transfer") // not in client's allowed scopes

	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_scope", decodeErrorCode(t, rr))
}

func TestBCAuthorize_MissingBindingMessage(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	form := bcAuthorizeForm()
	form.Set("binding_message", "")

	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_binding_message", decodeErrorCode(t, rr))
}

func TestBCAuthorize_BindingMessageTooLong(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	form := bcAuthorizeForm()
	form.Set("binding_message", strings.Repeat("a", oidc.BindingMessageMaxLen+1))

	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_binding_message", decodeErrorCode(t, rr))
}

func TestBCAuthorize_RejectsUnsupportedACR(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	form := bcAuthorizeForm()
	form.Set("acr_values", "urn:mfa-otp")

	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestBCAuthorize_ClampsRequestedExpiry(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	// Above the cap → clamped down to 900.
	form := bcAuthorizeForm()
	form.Set("requested_expiry", "5000")
	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp bcAuthorizeResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal(oidc.RequestedExpiryMax, resp.ExpiresIn)

	// Below the floor → clamped up.
	h.cibaReqs.issued = nil
	form.Set("requested_expiry", "10")
	rr = postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code)
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal(oidc.RequestedExpiryMin, resp.ExpiresIn)

	// Missing → falls through to default.
	h.cibaReqs.issued = nil
	form.Del("requested_expiry")
	rr = postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code)
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal(int((10 * time.Minute).Seconds()), resp.ExpiresIn)
}

func TestBCAuthorize_NotifierFailureReturns503(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)
	h.notifier.err = errors.New("telegram api down")

	rr := postCIBA(t, h.handler, bcAuthorizeForm(), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusServiceUnavailable, rr.Code)
	c.Equal("notifier_unavailable", decodeErrorCode(t, rr))
}

func TestBCAuthorize_LowercasesLoginHintBeforeLookup(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h) // stored as "alice@example.com"

	form := bcAuthorizeForm()
	form.Set("login_hint", "Alice@Example.com")

	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())
}

func TestBCAuthorize_PingClientRequiresClientNotificationToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)

	mode := domain.CIBADeliveryPing
	h.clients.byClientID["demo-rp"].BackchannelTokenDeliveryMode = &mode

	form := bcAuthorizeForm()
	form.Del("client_notification_token")

	rr := postCIBA(t, h.handler, form, basic("demo-rp", "super-secret"))
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestBuildApprovalURL(t *testing.T) {
	c := require.New(t)
	c.Equal("http://op.local:8081/ciba/approve?t=abc",
		buildApprovalURL("http://op.local:8081", "abc"))
	c.Equal("http://op.local:8081/ciba/approve?t=abc",
		buildApprovalURL("http://op.local:8081/", "abc"),
		"trailing slash on issuer must be trimmed")
}

func TestParseRequestedExpiry(t *testing.T) {
	c := require.New(t)
	c.Equal(0, parseRequestedExpiry(""))
	c.Equal(0, parseRequestedExpiry("not-a-number"))
	c.Equal(300, parseRequestedExpiry("300"))
}

// --- GET /ciba/approve ---

func TestApprove_RendersPageWithBinding(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	// Seed the stores by going through bc-authorize so the binding
	// message + approval token round-trip honestly.
	seedCIBAClient(t, h)
	seedCIBAUser(t, h)
	h.cibaReqs.nextID = "auth-req-xyz"
	h.approvalTks.next = "tok-abc"

	rr := postCIBA(t, h.handler, bcAuthorizeForm(), basic("demo-rp", "super-secret"))
	c.Equal(http.StatusOK, rr.Code)

	req := httptest.NewRequest(http.MethodGet, "/ciba/approve?t=tok-abc", nil)
	rec := httptest.NewRecorder()
	h.handler.Approve(rec, req)

	c.Equal(http.StatusOK, rec.Code)
	c.Contains(rec.Header().Get("Content-Type"), "text/html")
	c.Equal("no-store", rec.Header().Get("Cache-Control"))
	body := rec.Body.String()
	c.Contains(body, "Authorize $50 to Café Acme")
	c.Contains(body, "demo-rp")
	c.Contains(body, "tok-abc", "approval token must be embedded for the form submit")
	c.Contains(body, "/ciba/approve/login/begin")
	c.Contains(body, "/ciba/deny")
}

func TestApprove_MissingToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/ciba/approve", nil)
	rec := httptest.NewRecorder()
	h.handler.Approve(rec, req)

	c.Equal(http.StatusBadRequest, rec.Code)
	c.Contains(rec.Body.String(), "missing")
}

func TestApprove_UnknownToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/ciba/approve?t=never-issued", nil)
	rec := httptest.NewRecorder()
	h.handler.Approve(rec, req)

	c.Equal(http.StatusNotFound, rec.Code)
	c.Contains(rec.Body.String(), "expired or already been used")
}

func TestApprove_AlreadyApproved(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	// Bypass bc-authorize: seed the stores directly so we can flip
	// the status to approved.
	h.approvalTks.bound["tok-a"] = "auth-req-1"
	now := time.Now().UTC()
	h.cibaReqs.stored["auth-req-1"] = &domain.CIBARequest{
		ClientID:       "demo-rp",
		OPUserID:       uuid.New(),
		Scope:          []string{"openid"},
		BindingMessage: "Already done",
		Status:         domain.CIBAStatusApproved,
		IssuedAt:       now,
		ApprovedAt:     &now,
	}

	req := httptest.NewRequest(http.MethodGet, "/ciba/approve?t=tok-a", nil)
	rec := httptest.NewRecorder()
	h.handler.Approve(rec, req)

	c.Equal(http.StatusOK, rec.Code)
	c.Contains(rec.Body.String(), "already authorized")
	c.NotContains(rec.Body.String(), "Already done",
		"terminal page must not echo the binding message to drive-by visitors")
}

func TestApprove_AlreadyDenied(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	h.approvalTks.bound["tok-d"] = "auth-req-2"
	now := time.Now().UTC()
	h.cibaReqs.stored["auth-req-2"] = &domain.CIBARequest{
		ClientID:       "demo-rp",
		OPUserID:       uuid.New(),
		Scope:          []string{"openid"},
		BindingMessage: "Not happening",
		Status:         domain.CIBAStatusDenied,
		IssuedAt:       now,
		DeniedAt:       &now,
	}

	req := httptest.NewRequest(http.MethodGet, "/ciba/approve?t=tok-d", nil)
	rec := httptest.NewRecorder()
	h.handler.Approve(rec, req)

	c.Equal(http.StatusOK, rec.Code)
	c.Contains(rec.Body.String(), "already denied")
}

func TestApprove_PeekDoesNotConsumeOnReload(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	h.approvalTks.bound["tok-reload"] = "auth-req-3"
	now := time.Now().UTC()
	h.cibaReqs.stored["auth-req-3"] = &domain.CIBARequest{
		ClientID:       "demo-rp",
		BindingMessage: "Authorize $50",
		Status:         domain.CIBAStatusPending,
		IssuedAt:       now,
	}

	for i := range 3 {
		req := httptest.NewRequest(http.MethodGet, "/ciba/approve?t=tok-reload", nil)
		rec := httptest.NewRecorder()
		h.handler.Approve(rec, req)
		c.Equal(http.StatusOK, rec.Code, "reload %d must still render", i+1)
	}
}

// --- Action endpoints ---

// seedApprovalReady seeds the harness with a client, an op_user with a
// known passkey_user_id, and a pending CIBARequest + approval token.
// Returns the values the tests need to compose requests against.
func seedApprovalReady(t *testing.T, h *cibaHarness) (approvalToken, authReqID string, opUser *domain.OPUser, passkeyUserID uuid.UUID) {
	t.Helper()

	authReqID = "auth-req-xyz"
	approvalToken = "tok-xyz"
	passkeyUserID = uuid.New()

	opUser = &domain.OPUser{
		ID:            uuid.New(),
		Email:         "alice@example.com",
		DisplayName:   "Alice",
		PasskeyUserID: passkeyUserID,
	}
	h.usersByPasskey.byPasskeyID[passkeyUserID] = opUser

	h.cibaReqs.stored[authReqID] = &domain.CIBARequest{
		ClientID:       "demo-rp",
		OPUserID:       opUser.ID,
		Scope:          []string{"openid", "payment"},
		BindingMessage: "Authorize $50",
		Status:         domain.CIBAStatusPending,
		IssuedAt:       time.Now().UTC(),
	}
	h.approvalTks.bound[approvalToken] = authReqID

	return approvalToken, authReqID, opUser, passkeyUserID
}

func postJSONHandler(t *testing.T, fn http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}

func TestCIBALoginBegin_HappyPath(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, _, _, _ := seedApprovalReady(t, h)

	h.passkey.beginResp = passkey.BeginLoginResponse{
		Options:   json.RawMessage(`{"challenge":"abc"}`),
		SessionID: "pk-sess-1",
	}

	rr := postJSONHandler(t, h.handler.LoginBegin, map[string]string{"t": tok})
	c.Equal(http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	var resp approveLoginBeginResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("pk-sess-1", resp.SessionID)
	c.JSONEq(`{"challenge":"abc"}`, string(resp.Options))

	// Token is still valid for the subsequent ApproveSubmit — peek
	// must not consume.
	_, err := h.approvalTks.Peek(t.Context(), tok)
	c.NoError(err)
}

func TestCIBALoginBegin_UnknownToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	rr := postJSONHandler(t, h.handler.LoginBegin, map[string]string{"t": "ghost"})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeErrorCode(t, rr))
	c.Equal(0, h.passkey.beginCalls, "passkey service must not be called when the token is bad")
}

func TestCIBALoginBegin_MissingToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	rr := postJSONHandler(t, h.handler.LoginBegin, map[string]string{})
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestApproveSubmit_HappyPath_TransitionsToApproved(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, passkeyUserID := seedApprovalReady(t, h)

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: passkeyUserID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())

	// Status transitioned and approval token consumed.
	r := h.cibaReqs.stored[authReqID]
	c.Equal(domain.CIBAStatusApproved, r.Status)
	c.NotNil(r.ApprovedAt)

	_, err := h.approvalTks.Peek(t.Context(), tok)
	c.ErrorIs(err, domain.ErrApprovalTokenNotFound, "token must be consumed on approve")
}

func TestApproveSubmit_UserMismatch_DoesNotTransition(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, _ := seedApprovalReady(t, h)

	// Add a SECOND op_user with a different passkey id. CompleteLogin
	// returns that other passkey user — should be rejected.
	otherPasskeyID := uuid.New()
	otherUser := &domain.OPUser{
		ID:            uuid.New(),
		Email:         "mallory@example.com",
		DisplayName:   "Mallory",
		PasskeyUserID: otherPasskeyID,
	}
	h.usersByPasskey.byPasskeyID[otherPasskeyID] = otherUser

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: otherPasskeyID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusForbidden, rr.Code)
	c.Equal("user_mismatch", decodeErrorCode(t, rr))

	r := h.cibaReqs.stored[authReqID]
	c.Equal(domain.CIBAStatusPending, r.Status, "request must stay pending on user mismatch")
}

func TestApproveSubmit_UnknownPasskeyUser(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, _, _, _ := seedApprovalReady(t, h)

	// Passkey returns a user_id that doesn't map to any op_user.
	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: uuid.NewString(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusForbidden, rr.Code)
	c.Equal("user_mismatch", decodeErrorCode(t, rr))
}

func TestApproveSubmit_AlreadyDecided(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, passkeyUserID := seedApprovalReady(t, h)

	// Flip the request to already-approved.
	now := time.Now().UTC()
	h.cibaReqs.stored[authReqID].Status = domain.CIBAStatusApproved
	h.cibaReqs.stored[authReqID].ApprovedAt = &now

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: passkeyUserID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("already_decided", decodeErrorCode(t, rr))
}

func TestApproveSubmit_UnknownToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  "ghost",
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeErrorCode(t, rr))
	c.Empty(h.passkey.completeCalls, "passkey complete must not be called when the token is bad")
}

func TestApproveSubmit_MissingFields(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, _, _, _ := seedApprovalReady(t, h)

	cases := []map[string]any{
		{"passkey_session_id": "x", "credential": json.RawMessage(`{}`)},
		{"t": tok, "credential": json.RawMessage(`{}`)},
		{"t": tok, "passkey_session_id": "x"},
	}
	for i, body := range cases {
		rr := postJSONHandler(t, h.handler.ApproveSubmit, body)
		c.Equalf(http.StatusBadRequest, rr.Code, "case %d", i)
		c.Equalf("invalid_request", decodeErrorCode(t, rr), "case %d", i)
	}
}

func TestDeny_HappyPath(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, _ := seedApprovalReady(t, h)

	rr := postJSONHandler(t, h.handler.Deny, map[string]string{"t": tok})
	c.Equal(http.StatusNoContent, rr.Code, "body=%s", rr.Body.String())

	r := h.cibaReqs.stored[authReqID]
	c.Equal(domain.CIBAStatusDenied, r.Status)
	c.NotNil(r.DeniedAt)

	_, err := h.approvalTks.Peek(t.Context(), tok)
	c.ErrorIs(err, domain.ErrApprovalTokenNotFound, "token must be consumed on deny")
}

func TestDeny_UnknownToken(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)

	rr := postJSONHandler(t, h.handler.Deny, map[string]string{"t": "ghost"})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeErrorCode(t, rr))
}

func TestDeny_AlreadyDecided(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, _ := seedApprovalReady(t, h)

	now := time.Now().UTC()
	h.cibaReqs.stored[authReqID].Status = domain.CIBAStatusApproved
	h.cibaReqs.stored[authReqID].ApprovedAt = &now

	rr := postJSONHandler(t, h.handler.Deny, map[string]string{"t": tok})
	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("already_decided", decodeErrorCode(t, rr))
}

// --- Ping mode callback ---

func setClientPingMode(t *testing.T, h *cibaHarness, endpoint string) {
	t.Helper()
	mode := domain.CIBADeliveryPing
	h.clients.byClientID["demo-rp"] = &domain.Client{
		ID:                      uuid.New(),
		ClientID:                "demo-rp",
		ClientSecretHash:        bcryptHash(t, "super-secret"),
		GrantTypes:              []string{oidc.CIBAGrantType},
		Scopes:                  []string{"openid", "payment"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
		BackchannelTokenDeliveryMode: &mode,
		ClientNotificationEndpoint:   &endpoint,
	}
}

func TestApproveSubmit_PingClient_FiresCallback(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, passkeyUserID := seedApprovalReady(t, h)

	setClientPingMode(t, h, "https://rp.example.com/notify")
	h.cibaReqs.stored[authReqID].ClientNotificationToken = "rp-correlation-id"

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: passkeyUserID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusNoContent, rr.Code)

	c.Len(h.callback.calls, 1)
	got := h.callback.calls[0]
	c.Equal("https://rp.example.com/notify", got.Endpoint)
	c.Equal("rp-correlation-id", got.ClientNotificationToken)
	c.Equal(authReqID, got.AuthReqID)
}

func TestDeny_PingClient_FiresCallback(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, _ := seedApprovalReady(t, h)

	setClientPingMode(t, h, "https://rp.example.com/notify")
	h.cibaReqs.stored[authReqID].ClientNotificationToken = "rp-correlation-id"

	rr := postJSONHandler(t, h.handler.Deny, map[string]string{"t": tok})
	c.Equal(http.StatusNoContent, rr.Code)

	c.Len(h.callback.calls, 1)
	c.Equal(authReqID, h.callback.calls[0].AuthReqID)
}

func TestApproveSubmit_PollClient_DoesNotFireCallback(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, _, _, passkeyUserID := seedApprovalReady(t, h)

	// Default seeded client has no delivery mode set — treat as poll.
	h.clients.byClientID["demo-rp"] = &domain.Client{
		ClientID:                "demo-rp",
		GrantTypes:              []string{oidc.CIBAGrantType},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: passkeyUserID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusNoContent, rr.Code)
	c.Empty(h.callback.calls, "poll clients must not be notified")
}

func TestApproveSubmit_PingFailureDoesNotRollBack(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, passkeyUserID := seedApprovalReady(t, h)

	setClientPingMode(t, h, "https://rp.example.com/notify")
	h.cibaReqs.stored[authReqID].ClientNotificationToken = "rp-correlation-id"
	h.callback.err = errors.New("RP is down")

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: passkeyUserID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusNoContent, rr.Code,
		"a ping failure must not change the user-facing response — the RP can still poll")
	c.Equal(domain.CIBAStatusApproved, h.cibaReqs.stored[authReqID].Status)
}

func TestApproveSubmit_PingClient_WithoutEndpoint_SilentlySkipped(t *testing.T) {
	c := require.New(t)
	h := newCIBAHarness(t)
	tok, authReqID, _, passkeyUserID := seedApprovalReady(t, h)

	mode := domain.CIBADeliveryPing
	h.clients.byClientID["demo-rp"] = &domain.Client{
		ClientID:                "demo-rp",
		GrantTypes:              []string{oidc.CIBAGrantType},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
		BackchannelTokenDeliveryMode: &mode,
		// no ClientNotificationEndpoint
	}
	h.cibaReqs.stored[authReqID].ClientNotificationToken = "rp-correlation-id"

	h.passkey.completeResp = passkey.CompleteLoginResponse{
		UserID: passkeyUserID.String(),
	}

	rr := postJSONHandler(t, h.handler.ApproveSubmit, map[string]any{
		"t":                  tok,
		"passkey_session_id": "pk-sess-1",
		"credential":         json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusNoContent, rr.Code)
	c.Empty(h.callback.calls)
}
