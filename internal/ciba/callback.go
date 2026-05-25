// Package ciba holds the OP-side CIBA mechanisms that live outside the
// HTTP handler — today that means the client-notification callback the
// OP invokes against the RP in ping and push delivery modes.
package ciba

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Sentinel errors returned by CallbackClient.
var (
	// ErrCallbackTransport wraps a network / protocol failure talking
	// to the RP's notification endpoint.
	ErrCallbackTransport = errors.New("ciba: callback transport error")
	// ErrCallbackNon2xx is returned when the RP responds with a non-2xx
	// status. The OP treats this as recoverable: ping clients can fall
	// back to polling, and the OP-side state (status + tokens) does not
	// roll back on RP-side failure.
	ErrCallbackNon2xx = errors.New("ciba: callback returned non-2xx")
)

// CallbackClient POSTs the CIBA client-notification endpoint with the
// payload appropriate to the client's delivery mode. The token in the
// Authorization header is the client_notification_token the RP provided
// at /bc-authorize, used per CIBA §10.2 as the bearer credential.
//
// The client is best-effort by design: a failure here does not roll back
// any OP-side state. ping clients can still poll /oidc/token to collect
// tokens; push clients lose the deliverable but the CIBARequest stays
// approved so a manual recovery via polling still works.
type CallbackClient struct {
	http *http.Client
}

// CallbackOption customizes a CallbackClient.
type CallbackOption func(*CallbackClient)

// WithCallbackHTTPClient overrides the default *http.Client. Useful for
// custom timeouts, transport, or tests pointing at an httptest server.
func WithCallbackHTTPClient(c *http.Client) CallbackOption {
	return func(cb *CallbackClient) { cb.http = c }
}

// NewCallbackClient returns a CallbackClient ready to talk to RP
// notification endpoints. The default HTTP client carries a 5-second
// per-attempt timeout — enough for a healthy RP and short enough to
// keep the user-facing approval page responsive.
func NewCallbackClient(opts ...CallbackOption) *CallbackClient {
	c := &CallbackClient{
		http: &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// PingPayload is the body POSTed in ping-mode delivery: a bare
// auth_req_id so the RP can call back into /oidc/token to collect
// tokens. CIBA §10.2.
type PingPayload struct {
	AuthReqID string `json:"auth_req_id"`
}

// PushPayload is the body POSTed in push-mode delivery: the full token
// response, formatted identically to /oidc/token. CIBA §10.3. Used by
// the push wiring in a later phase; declared here so the wire shape
// lives in one place.
type PushPayload struct {
	AuthReqID    string `json:"auth_req_id"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// Ping POSTs a PingPayload to endpoint with the given client
// notification token as the Bearer credential. The OP uses Ping when
// the client's backchannel_token_delivery_mode is "ping".
func (c *CallbackClient) Ping(ctx context.Context, endpoint, clientNotificationToken, authReqID string) error {
	return c.post(ctx, endpoint, clientNotificationToken, PingPayload{AuthReqID: authReqID})
}

// Push POSTs a PushPayload to endpoint with the given client
// notification token as the Bearer credential. The OP uses Push when
// the client's backchannel_token_delivery_mode is "push".
func (c *CallbackClient) Push(ctx context.Context, endpoint, clientNotificationToken string, payload PushPayload) error {
	return c.post(ctx, endpoint, clientNotificationToken, payload)
}

func (c *CallbackClient) post(ctx context.Context, endpoint, bearer string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", ErrCallbackTransport, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrCallbackTransport, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCallbackTransport, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: status %d: %s", ErrCallbackNon2xx, resp.StatusCode, string(preview))
	}

	return nil
}
