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
	nextID string
	err    error
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
	if f.nextID == "" {
		return uuid.NewString(), nil
	}
	return f.nextID, nil
}

type fakeApprovalTokens struct {
	mu     sync.Mutex
	issued []string
	next   string
	err    error
}

func (f *fakeApprovalTokens) Issue(_ context.Context, authReqID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.issued = append(f.issued, authReqID)
	if f.next == "" {
		return "tok-" + authReqID, nil
	}
	return f.next, nil
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
	clients     *fakeClients
	users       *fakeOPUsersByEmail
	cibaReqs    *fakeCIBARequestIssuer
	approvalTks *fakeApprovalTokens
	notifier    *fakeNotifier
	handler     *CIBAHandler
}

func newCIBAHarness(t *testing.T) *cibaHarness {
	t.Helper()

	clients := &fakeClients{byClientID: map[string]*domain.Client{}}
	users := &fakeOPUsersByEmail{byEmail: map[string]*domain.OPUser{}}
	cibaReqs := &fakeCIBARequestIssuer{}
	approvals := &fakeApprovalTokens{}
	n := &fakeNotifier{}

	return &cibaHarness{
		clients:     clients,
		users:       users,
		cibaReqs:    cibaReqs,
		approvalTks: approvals,
		notifier:    n,
		handler: NewCIBAHandler(CIBAHandlerDeps{
			Clients:        clients,
			Users:          users,
			CIBARequests:   cibaReqs,
			ApprovalTokens: approvals,
			Notifier:       n,
			Issuer:         "http://op.local:8081",
			DefaultTTL:     10 * time.Minute,
			PollInterval:   5,
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
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
