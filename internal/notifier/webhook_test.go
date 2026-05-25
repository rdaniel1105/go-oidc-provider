package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebhookNotifier_PostsExpectedPayload(t *testing.T) {
	c := require.New(t)

	var received webhookPayload
	var headers http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(srv.URL,
		WithWebhookAuthHeader("Bearer shared-secret"),
	)

	user := sampleUser()
	c.NoError(n.Notify(context.Background(), Notification{
		User:           user,
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	}))

	c.Equal(user.ID.String(), received.OPUserID)
	c.Equal("alice@example.com", received.Email)
	c.Equal("+573001234567", received.PhoneE164)
	c.Equal("Demo RP", received.ClientName)
	c.Equal("Authorize $50", received.BindingMessage)
	c.Equal("https://op.local:8081/ciba/approve?t=abc", received.ApprovalURL)
	c.Equal("application/json", headers.Get("Content-Type"))
	c.Equal("Bearer shared-secret", headers.Get("Authorization"))
}

func TestWebhookNotifier_OmitsPhoneWhenAbsent(t *testing.T) {
	c := require.New(t)

	var received webhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	user := sampleUser()
	user.PhoneE164 = nil

	c.NoError(NewWebhookNotifier(srv.URL).Notify(context.Background(), Notification{
		User:           user,
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	}))

	c.Empty(received.PhoneE164)
}

func TestWebhookNotifier_NonTwoXX(t *testing.T) {
	c := require.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "downstream is sad", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := NewWebhookNotifier(srv.URL).Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	})
	c.ErrorIs(err, ErrWebhookNon2xx)
}

func TestWebhookNotifier_TransportError(t *testing.T) {
	c := require.New(t)

	// Closed port — the request can't connect.
	err := NewWebhookNotifier("http://127.0.0.1:1").Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	})
	c.Error(err)
	c.NotErrorIs(err, ErrWebhookNon2xx, "transport failure must not look like a non-2xx response")
}
