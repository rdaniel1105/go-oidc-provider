// Package passkey wraps the HTTP API of the go-passkey-auth service. The
// OP delegates every WebAuthn ceremony to that service; this package keeps
// the wire shapes in one place so handlers and the CIBA approval flow can
// treat passkey operations as plain Go function calls.
//
// The browser still performs the actual navigator.credentials.create /
// .get calls. The OP renders the page, brokers /begin and /complete via
// this client, and never sees the raw private credential material —
// only the attestation / assertion bytes the authenticator emits.
package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Sentinel errors returned by Client methods.
var (
	// ErrTransport wraps any network or protocol-level failure talking to
	// the passkey service (connection refused, timeout, malformed JSON).
	// Callers should treat this as a transient infrastructure problem.
	ErrTransport = errors.New("passkey: transport error")
	// ErrServiceUnavailable is returned when the passkey service replies
	// with a 5xx status. Distinct from ErrTransport so the OP can choose
	// to retry differently (e.g. circuit-break) vs. an unreachable host.
	ErrServiceUnavailable = errors.New("passkey: service unavailable")
)

// ErrService is returned when the passkey service responds with a 4xx
// status carrying a stable error code. The Code field is the value of
// the "error" key in the JSON body; the Status field is the HTTP status.
type ErrService struct {
	// Status is the HTTP status returned by the passkey service.
	Status int
	// Code is the stable error identifier in the response body
	// (e.g. "username_taken", "invalid_request"). Empty if the body did
	// not parse as the expected envelope.
	Code string
}

// Error implements the error interface.
func (e *ErrService) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("passkey: service returned %d", e.Status)
	}
	return fmt.Sprintf("passkey: service returned %d: %s", e.Status, e.Code)
}

// Client talks to a go-passkey-auth instance over HTTP. The zero value is
// not usable; construct with New.
type Client struct {
	baseURL string
	http    *http.Client
}

// Option customizes a Client.
type Option func(*Client)

// WithHTTPClient overrides the default *http.Client. Use for custom
// timeouts, transport, or tracing.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// New returns a Client targeting baseURL (e.g. "http://passkey:8080").
// Trailing slashes on baseURL are tolerated.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// BeginRegister starts a passkey registration ceremony for the given
// username and display name. The returned Options is opaque JSON the
// caller must pass to navigator.credentials.create in the browser;
// SessionID is the handle that ties the eventual /complete call to the
// challenge stored server-side.
func (c *Client) BeginRegister(ctx context.Context, req BeginRegisterRequest) (BeginRegisterResponse, error) {
	var out BeginRegisterResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/register/begin", req, &out)
	return out, err
}

// CompleteRegister submits the authenticator's attestation response.
// On success the passkey service has created the user row and persisted
// the credential.
func (c *Client) CompleteRegister(ctx context.Context, req CompleteRegisterRequest) (CompleteRegisterResponse, error) {
	var out CompleteRegisterResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/register/complete", req, &out)
	return out, err
}

// BeginLogin starts a discoverable passkey login ceremony. No username is
// required — the authenticator resolves which credential to use.
func (c *Client) BeginLogin(ctx context.Context) (BeginLoginResponse, error) {
	var out BeginLoginResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/login/begin", struct{}{}, &out)
	return out, err
}

// CompleteLogin submits the authenticator's assertion response. The
// returned UserID is the passkey-side user identifier; CIBA approval and
// auth-code login use this value to look up the matching op_user.
func (c *Client) CompleteLogin(ctx context.Context, req CompleteLoginRequest) (CompleteLoginResponse, error) {
	var out CompleteLoginResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/auth/login/complete", req, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: marshal request: %v", ErrTransport, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrTransport, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: read body: %v", ErrTransport, err)
	}

	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: %d %s", ErrServiceUnavailable, resp.StatusCode, string(respBody))
	}

	if resp.StatusCode >= 400 {
		return decodeErrService(resp.StatusCode, respBody)
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%w: decode response: %v", ErrTransport, err)
		}
	}

	return nil
}

func decodeErrService(status int, body []byte) error {
	var envelope struct {
		Error string `json:"error"`
	}

	_ = json.Unmarshal(body, &envelope)

	return &ErrService{Status: status, Code: envelope.Error}
}
