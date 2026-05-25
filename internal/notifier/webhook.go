package notifier

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

// Sentinel errors returned by WebhookNotifier.
var (
	// ErrWebhookNon2xx is returned when the configured webhook URL
	// responded with a non-2xx status. Wrap it with errors.Is to react.
	ErrWebhookNon2xx = errors.New("notifier: webhook returned non-2xx")
)

// WebhookNotifier POSTs the notification payload as JSON to a configured
// URL. Intended for native-app integrations (e.g. an Auth0-Guardian-
// style mobile app) where the OP doesn't know how the device actually
// renders the approval prompt — it just forwards the data.
//
// The wire shape is intentionally minimal and stable; once an
// integration ships against it, it will not change without a versioned
// header.
type WebhookNotifier struct {
	url    string
	http   *http.Client
	header string
}

// WebhookOption customizes a WebhookNotifier.
type WebhookOption func(*WebhookNotifier)

// WithWebhookHTTPClient overrides the default *http.Client. Useful for
// custom timeouts, transport, or tracing.
func WithWebhookHTTPClient(c *http.Client) WebhookOption {
	return func(n *WebhookNotifier) { n.http = c }
}

// WithWebhookAuthHeader sets an Authorization header sent on every
// request (e.g. "Bearer <shared-secret>"). Empty disables it.
func WithWebhookAuthHeader(value string) WebhookOption {
	return func(n *WebhookNotifier) { n.header = value }
}

// NewWebhookNotifier returns a WebhookNotifier targeting url.
func NewWebhookNotifier(url string, opts ...WebhookOption) *WebhookNotifier {
	n := &WebhookNotifier{
		url:  url,
		http: &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// webhookPayload is the JSON body POSTed to the configured webhook URL.
// Field names follow the OIDC / CIBA terminology so the receiver can map
// values straight into their app without translation.
type webhookPayload struct {
	OPUserID       string `json:"op_user_id"`
	Email          string `json:"email,omitempty"`
	PhoneE164      string `json:"phone_e164,omitempty"`
	ClientName     string `json:"client_name"`
	BindingMessage string `json:"binding_message"`
	ApprovalURL    string `json:"approval_url"`
}

// Notify marshals the notification as JSON and POSTs it to the
// configured URL. Returns ErrWebhookNon2xx for any non-2xx response.
func (n *WebhookNotifier) Notify(ctx context.Context, in Notification) error {
	payload := webhookPayload{
		OPUserID:       in.User.ID.String(),
		Email:          in.User.Email,
		ClientName:     in.ClientName,
		BindingMessage: in.BindingMessage,
		ApprovalURL:    in.ApprovalURL,
	}
	if in.User.PhoneE164 != nil {
		payload.PhoneE164 = *in.User.PhoneE164
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notifier: marshal webhook body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notifier: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if n.header != "" {
		req.Header.Set("Authorization", n.header)
	}

	resp, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("notifier: webhook POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: status %d: %s", ErrWebhookNon2xx, resp.StatusCode, string(preview))
	}

	return nil
}
