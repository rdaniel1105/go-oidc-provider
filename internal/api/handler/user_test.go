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
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
)

// --- fakes ---

type fakeSignupStore struct {
	mu    sync.Mutex
	saved map[string]domain.SignupState
}

func newFakeSignupStore() *fakeSignupStore {
	return &fakeSignupStore{saved: map[string]domain.SignupState{}}
}

func (f *fakeSignupStore) Save(_ context.Context, sessionID string, state domain.SignupState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved[sessionID] = state
	return nil
}

func (f *fakeSignupStore) Consume(_ context.Context, sessionID string) (domain.SignupState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.saved[sessionID]
	if !ok {
		return domain.SignupState{}, domain.ErrSignupStateNotFound
	}
	delete(f.saved, sessionID)
	return s, nil
}

type fakeUserCreator struct {
	mu      sync.Mutex
	created []*domain.OPUser
	err     error
}

func (f *fakeUserCreator) Create(_ context.Context, u *domain.OPUser) (*domain.OPUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	u.ID = uuid.New()
	f.created = append(f.created, u)
	return u, nil
}

type fakePasskey struct {
	beginResp     passkey.BeginRegisterResponse
	beginErr      error
	completeResp  passkey.CompleteRegisterResponse
	completeErr   error
	beginCalls    []passkey.BeginRegisterRequest
	completeCalls []passkey.CompleteRegisterRequest
}

func (f *fakePasskey) BeginRegister(_ context.Context, req passkey.BeginRegisterRequest) (passkey.BeginRegisterResponse, error) {
	f.beginCalls = append(f.beginCalls, req)
	return f.beginResp, f.beginErr
}

func (f *fakePasskey) CompleteRegister(_ context.Context, req passkey.CompleteRegisterRequest) (passkey.CompleteRegisterResponse, error) {
	f.completeCalls = append(f.completeCalls, req)
	return f.completeResp, f.completeErr
}

func newUserHandler(t *testing.T, p *fakePasskey, sigs *fakeSignupStore, users *fakeUserCreator) *UserHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewUserHandler(p, sigs, users, logger)
}

func postJSON(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func decodeErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var env errorEnvelope
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&env))
	return env.Code
}

// --- Begin ---

func TestUserHandler_Begin_HappyPath(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{beginResp: passkey.BeginRegisterResponse{
		Options:   json.RawMessage(`{"challenge":"x"}`),
		SessionID: "sess-1",
	}}
	sigs := newFakeSignupStore()
	users := &fakeUserCreator{}
	h := newUserHandler(t, p, sigs, users)

	rr := postJSON(t, h.Begin, map[string]string{
		"email":        "Alice@Example.com",
		"display_name": "Alice",
		"phone_e164":   "+573001234567",
	})
	c.Equal(http.StatusOK, rr.Code)

	var resp beginResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.Equal("sess-1", resp.SessionID)
	c.JSONEq(`{"challenge":"x"}`, string(resp.Options))

	c.Len(p.beginCalls, 1)
	c.Equal("alice@example.com", p.beginCalls[0].Username, "email is lowercased before going to the passkey service")
	c.Equal("Alice", p.beginCalls[0].DisplayName)

	saved, ok := sigs.saved["sess-1"]
	c.True(ok)
	c.Equal("alice@example.com", saved.Email)
	c.Equal("Alice", saved.DisplayName)
	c.NotNil(saved.PhoneE164)
	c.Equal("+573001234567", *saved.PhoneE164)
}

func TestUserHandler_Begin_MissingFields(t *testing.T) {
	c := require.New(t)

	cases := []struct {
		name string
		body map[string]string
	}{
		{"missing email", map[string]string{"display_name": "Alice"}},
		{"malformed email", map[string]string{"email": "no-at-sign", "display_name": "Alice"}},
		{"missing display_name", map[string]string{"email": "a@b.com"}},
		{"bad phone", map[string]string{"email": "a@b.com", "display_name": "Alice", "phone_e164": "555-1234"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakePasskey{}
			h := newUserHandler(t, p, newFakeSignupStore(), &fakeUserCreator{})
			rr := postJSON(t, h.Begin, tc.body)
			c.Equal(http.StatusBadRequest, rr.Code)
			c.Equal("invalid_request", decodeErrorCode(t, rr))
			c.Empty(p.beginCalls, "passkey service must not be called on invalid input")
		})
	}
}

func TestUserHandler_Begin_PasskeyServiceErrorMapsToConflict(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{beginErr: &passkey.ServiceError{Status: http.StatusConflict, Code: "username_taken"}}
	h := newUserHandler(t, p, newFakeSignupStore(), &fakeUserCreator{})

	rr := postJSON(t, h.Begin, map[string]string{"email": "a@b.com", "display_name": "Alice"})
	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("email_taken", decodeErrorCode(t, rr))
}

func TestUserHandler_Begin_PasskeyUnavailableMapsToBadGateway(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{beginErr: passkey.ErrServiceUnavailable}
	h := newUserHandler(t, p, newFakeSignupStore(), &fakeUserCreator{})

	rr := postJSON(t, h.Begin, map[string]string{"email": "a@b.com", "display_name": "Alice"})
	c.Equal(http.StatusBadGateway, rr.Code)
	c.Equal("service_unavailable", decodeErrorCode(t, rr))
}

// --- Complete ---

func TestUserHandler_Complete_HappyPath(t *testing.T) {
	c := require.New(t)

	passkeyUserID := uuid.New()

	p := &fakePasskey{completeResp: passkey.CompleteRegisterResponse{
		UserID:       passkeyUserID.String(),
		CredentialID: "cred-1",
	}}
	sigs := newFakeSignupStore()
	phone := "+573001234567"
	sigs.saved["sess-1"] = domain.SignupState{
		Email:       "alice@example.com",
		DisplayName: "Alice",
		PhoneE164:   &phone,
	}
	users := &fakeUserCreator{}
	h := newUserHandler(t, p, sigs, users)

	rr := postJSON(t, h.Complete, map[string]any{
		"session_id": "sess-1",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusCreated, rr.Code)

	var resp completeResponse
	c.NoError(json.NewDecoder(rr.Body).Decode(&resp))
	c.NotEqual(uuid.Nil, resp.OPUserID)
	c.Equal(passkeyUserID.String(), resp.PasskeyUserID)

	c.Len(users.created, 1)
	created := users.created[0]
	c.Equal("alice@example.com", created.Email)
	c.Equal(passkeyUserID, created.PasskeyUserID)
	c.NotNil(created.PhoneE164)
	c.Equal("+573001234567", *created.PhoneE164)

	_, ok := sigs.saved["sess-1"]
	c.False(ok, "signup state must be consumed on success")
}

func TestUserHandler_Complete_MissingFields(t *testing.T) {
	c := require.New(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing session_id", map[string]any{"credential": json.RawMessage(`{"id":"x"}`)}},
		{"missing credential", map[string]any{"session_id": "sess-1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUserHandler(t, &fakePasskey{}, newFakeSignupStore(), &fakeUserCreator{})
			rr := postJSON(t, h.Complete, tc.body)
			c.Equal(http.StatusBadRequest, rr.Code)
			c.Equal("invalid_request", decodeErrorCode(t, rr))
		})
	}
}

func TestUserHandler_Complete_UnknownSessionID(t *testing.T) {
	c := require.New(t)

	h := newUserHandler(t, &fakePasskey{}, newFakeSignupStore(), &fakeUserCreator{})

	rr := postJSON(t, h.Complete, map[string]any{
		"session_id": "ghost",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusUnauthorized, rr.Code)
	c.Equal("session_invalid", decodeErrorCode(t, rr))
}

func TestUserHandler_Complete_PasskeyServiceRejects(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{completeErr: &passkey.ServiceError{Status: http.StatusBadRequest, Code: "attestation_rejected"}}
	sigs := newFakeSignupStore()
	sigs.saved["sess-1"] = domain.SignupState{Email: "a@b.com", DisplayName: "A"}
	h := newUserHandler(t, p, sigs, &fakeUserCreator{})

	rr := postJSON(t, h.Complete, map[string]any{
		"session_id": "sess-1",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusBadRequest, rr.Code)
	c.Equal("invalid_request", decodeErrorCode(t, rr))
}

func TestUserHandler_Complete_PasskeyReturnsInvalidUserID(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{completeResp: passkey.CompleteRegisterResponse{
		UserID:       "not-a-uuid",
		CredentialID: "cred-1",
	}}
	sigs := newFakeSignupStore()
	sigs.saved["sess-1"] = domain.SignupState{Email: "a@b.com", DisplayName: "A"}
	h := newUserHandler(t, p, sigs, &fakeUserCreator{})

	rr := postJSON(t, h.Complete, map[string]any{
		"session_id": "sess-1",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusBadGateway, rr.Code)
	c.Equal("service_unavailable", decodeErrorCode(t, rr))
}

func TestUserHandler_Complete_EmailTakenAtCreate(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{completeResp: passkey.CompleteRegisterResponse{
		UserID:       uuid.NewString(),
		CredentialID: "cred-1",
	}}
	sigs := newFakeSignupStore()
	sigs.saved["sess-1"] = domain.SignupState{Email: "a@b.com", DisplayName: "A"}
	users := &fakeUserCreator{err: domain.ErrEmailTaken}
	h := newUserHandler(t, p, sigs, users)

	rr := postJSON(t, h.Complete, map[string]any{
		"session_id": "sess-1",
		"credential": json.RawMessage(`{"id":"x"}`),
	})
	c.Equal(http.StatusConflict, rr.Code)
	c.Equal("email_taken", decodeErrorCode(t, rr))
}

// --- sanity ---

func TestLooksLikeE164(t *testing.T) {
	c := require.New(t)

	c.True(looksLikeE164("+573001234567"))
	c.True(looksLikeE164("+15551234567"))
	c.False(looksLikeE164("573001234567"), "must start with +")
	c.False(looksLikeE164("+57300"), "too short")
	c.False(looksLikeE164("+573-001-234-567"), "no dashes")
	c.False(looksLikeE164("+57300abc4567"), "no letters")
}

// Sanity that *passkey.Client implements the passkeyClient interface that
// the handler depends on — keeps the production wiring from drifting.
var _ passkeyClient = (*passkey.Client)(nil)

// Sanity that the in-memory fakes satisfy the unexported interfaces used
// by the handler. The blank identifier assignments are a compile-time
// check; if signatures drift the tests stop building.
var (
	_ signupStore   = (*fakeSignupStore)(nil)
	_ opUserCreator = (*fakeUserCreator)(nil)
)

// Sanity that mapPasskeyError handles a generic transport error.
func TestUserHandler_Begin_TransportErrorMapsToBadGateway(t *testing.T) {
	c := require.New(t)

	p := &fakePasskey{beginErr: errors.New("dial tcp: connection refused")}
	// Wrap to look like ErrTransport without going through actual transport.
	p.beginErr = wrapTransport(p.beginErr)

	h := newUserHandler(t, p, newFakeSignupStore(), &fakeUserCreator{})
	rr := postJSON(t, h.Begin, map[string]string{"email": "a@b.com", "display_name": "Alice"})
	c.Equal(http.StatusBadGateway, rr.Code)
	c.Equal("service_unavailable", decodeErrorCode(t, rr))
}

// wrapTransport returns an error whose chain includes passkey.ErrTransport
// so the handler's errors.Is check matches.
func wrapTransport(inner error) error {
	return errTransportWrapper{inner: inner}
}

type errTransportWrapper struct{ inner error }

func (e errTransportWrapper) Error() string { return e.inner.Error() }
func (e errTransportWrapper) Unwrap() error { return passkey.ErrTransport }
