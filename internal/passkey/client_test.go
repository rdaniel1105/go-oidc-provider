package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordedCall struct {
	Method      string
	Path        string
	ContentType string
	Body        []byte
}

// fakePasskeyService stands in for go-passkey-auth in tests. It records
// the calls it received and returns the canned response for each path.
type fakePasskeyService struct {
	server *httptest.Server
	calls  []recordedCall
	// handlers maps "METHOD path" → response generator
	handlers map[string]func(*http.Request) (int, []byte)
}

func newFakePasskeyService(t *testing.T) *fakePasskeyService {
	t.Helper()
	f := &fakePasskeyService{handlers: map[string]func(*http.Request) (int, []byte){}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakePasskeyService) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.calls = append(f.calls, recordedCall{
		Method:      r.Method,
		Path:        r.URL.Path,
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
	})

	key := r.Method + " " + r.URL.Path
	if h, ok := f.handlers[key]; ok {
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		status, resp := h(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(resp)
		return
	}

	http.NotFound(w, r)
}

func (f *fakePasskeyService) on(method, path string, status int, body any) {
	raw, _ := json.Marshal(body)
	f.handlers[method+" "+path] = func(_ *http.Request) (int, []byte) {
		return status, raw
	}
}

func (f *fakePasskeyService) onRaw(method, path string, status int, body string) {
	f.handlers[method+" "+path] = func(_ *http.Request) (int, []byte) {
		return status, []byte(body)
	}
}

func TestClient_BeginRegister_SendsAndDecodes(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.on(http.MethodPost, "/api/v1/auth/register/begin", http.StatusOK, BeginRegisterResponse{
		Options:   json.RawMessage(`{"challenge":"abc","rp":{"id":"localhost"}}`),
		SessionID: "sess-1",
	})

	client := New(fake.server.URL)
	resp, err := client.BeginRegister(context.Background(), BeginRegisterRequest{
		Username:    "op-user-id-1",
		DisplayName: "Alice",
	})
	c.NoError(err)
	c.Equal("sess-1", resp.SessionID)
	c.JSONEq(`{"challenge":"abc","rp":{"id":"localhost"}}`, string(resp.Options))

	c.Len(fake.calls, 1)
	c.Equal(http.MethodPost, fake.calls[0].Method)
	c.Equal("/api/v1/auth/register/begin", fake.calls[0].Path)
	c.Equal("application/json", fake.calls[0].ContentType)
	c.JSONEq(`{"username":"op-user-id-1","display_name":"Alice"}`, string(fake.calls[0].Body))
}

func TestClient_CompleteRegister_ReturnsUserIDAndCredentialID(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.on(http.MethodPost, "/api/v1/auth/register/complete", http.StatusOK, CompleteRegisterResponse{
		UserID:       "passkey-user-uuid",
		CredentialID: "cred-abc",
	})

	client := New(fake.server.URL)
	resp, err := client.CompleteRegister(context.Background(), CompleteRegisterRequest{
		SessionID:  "sess-1",
		Credential: json.RawMessage(`{"id":"x"}`),
	})
	c.NoError(err)
	c.Equal("passkey-user-uuid", resp.UserID)
	c.Equal("cred-abc", resp.CredentialID)
}

func TestClient_BeginLogin_HasNoBodyFields(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.on(http.MethodPost, "/api/v1/auth/login/begin", http.StatusOK, BeginLoginResponse{
		Options:   json.RawMessage(`{"challenge":"def"}`),
		SessionID: "sess-2",
	})

	client := New(fake.server.URL)
	resp, err := client.BeginLogin(context.Background())
	c.NoError(err)
	c.Equal("sess-2", resp.SessionID)

	c.JSONEq(`{}`, string(fake.calls[0].Body))
}

func TestClient_CompleteLogin_ReturnsUserID(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.on(http.MethodPost, "/api/v1/auth/login/complete", http.StatusOK, CompleteLoginResponse{
		UserID:      "passkey-user-uuid",
		Username:    "op-user-id-1",
		DisplayName: "Alice",
	})

	client := New(fake.server.URL)
	resp, err := client.CompleteLogin(context.Background(), CompleteLoginRequest{
		SessionID:  "sess-2",
		Credential: json.RawMessage(`{"id":"x"}`),
	})
	c.NoError(err)
	c.Equal("passkey-user-uuid", resp.UserID)
	c.Equal("op-user-id-1", resp.Username)
	c.Equal("Alice", resp.DisplayName)
}

func TestClient_ErrService_DecodesErrorCode(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.onRaw(http.MethodPost, "/api/v1/auth/register/begin", http.StatusConflict, `{"error":"username_taken"}`)

	client := New(fake.server.URL)
	_, err := client.BeginRegister(context.Background(), BeginRegisterRequest{
		Username:    "alice",
		DisplayName: "Alice",
	})

	var serr *ErrService
	c.ErrorAs(err, &serr)
	c.Equal(http.StatusConflict, serr.Status)
	c.Equal("username_taken", serr.Code)
}

func TestClient_5xx_MapsToServiceUnavailable(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.onRaw(http.MethodPost, "/api/v1/auth/login/begin", http.StatusBadGateway, `upstream broke`)

	client := New(fake.server.URL)
	_, err := client.BeginLogin(context.Background())
	c.ErrorIs(err, ErrServiceUnavailable)
}

func TestClient_TransportError(t *testing.T) {
	c := require.New(t)

	client := New("http://127.0.0.1:1")
	_, err := client.BeginLogin(context.Background())
	c.ErrorIs(err, ErrTransport)
}

func TestClient_TrimsTrailingSlash(t *testing.T) {
	c := require.New(t)
	fake := newFakePasskeyService(t)

	fake.on(http.MethodPost, "/api/v1/auth/register/begin", http.StatusOK, BeginRegisterResponse{
		SessionID: "ok",
	})

	client := New(fake.server.URL + "/")
	_, err := client.BeginRegister(context.Background(), BeginRegisterRequest{
		Username:    "x",
		DisplayName: "X",
	})
	c.NoError(err)
	c.Len(fake.calls, 1, "trailing slash on baseURL must not produce double-slash 404")
}

func TestErrService_ErrorString(t *testing.T) {
	c := require.New(t)

	e := &ErrService{Status: http.StatusBadRequest, Code: "invalid_request"}
	c.Contains(e.Error(), "400")
	c.Contains(e.Error(), "invalid_request")

	bare := &ErrService{Status: http.StatusNotFound}
	c.Contains(bare.Error(), "404")
	c.NotContains(bare.Error(), "invalid_request", "bare error must not carry an extra code")
	// errors.Is between different ErrService instances should be false.
	c.False(errors.Is(e, bare))
}
