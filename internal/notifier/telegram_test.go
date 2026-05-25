package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTelegramFake(t *testing.T, ok bool, errorCode int, description string) (*httptest.Server, *sendMessageRequest, *http.Header) {
	t.Helper()
	var captured sendMessageRequest
	var headers http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()

		// The path embeds the bot token; we don't assert on the value
		// here (the test handler is bound to any path under /bot.../).
		require.True(t, strings.Contains(r.URL.Path, "/bot"))
		require.True(t, strings.HasSuffix(r.URL.Path, "/sendMessage"))

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)

		resp := sendMessageResponse{OK: ok, ErrorCode: errorCode, Description: description}
		out, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)

	return srv, &captured, &headers
}

func TestTelegramNotifier_HappyPath_BuildsExpectedMessage(t *testing.T) {
	c := require.New(t)

	srv, captured, headers := newTelegramFake(t, true, 0, "")

	n := NewTelegramNotifier("test-bot-token", "555",
		WithTelegramAPIRoot(srv.URL),
	)

	c.NoError(n.Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Café <Acme>",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	}))

	c.Equal("555", captured.ChatID)
	c.Equal("HTML", captured.ParseMode)
	c.Contains(captured.Text, "Café &lt;Acme&gt;", "client name must be HTML-escaped")
	c.Contains(captured.Text, "Authorize $50")

	c.Len(captured.ReplyMarkup.InlineKeyboard, 1)
	c.Len(captured.ReplyMarkup.InlineKeyboard[0], 1)
	c.Equal("Authorize", captured.ReplyMarkup.InlineKeyboard[0][0].Text)
	c.Equal("https://op.local:8081/ciba/approve?t=abc", captured.ReplyMarkup.InlineKeyboard[0][0].URL)

	c.Equal("application/json", headers.Get("Content-Type"))
}

func TestTelegramNotifier_APIError(t *testing.T) {
	c := require.New(t)

	srv, _, _ := newTelegramFake(t, false, 400, "chat not found")

	n := NewTelegramNotifier("bad-token", "555", WithTelegramAPIRoot(srv.URL))

	err := n.Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	})
	c.ErrorIs(err, ErrTelegramAPI)
	c.Contains(err.Error(), "chat not found")
}

func TestTelegramNotifier_TransportError(t *testing.T) {
	c := require.New(t)

	n := NewTelegramNotifier("x", "555", WithTelegramAPIRoot("http://127.0.0.1:1"))
	err := n.Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	})
	c.Error(err)
	c.NotErrorIs(err, ErrTelegramAPI)
}

func TestTelegramNotifier_PathEmbedsBotToken(t *testing.T) {
	c := require.New(t)

	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		resp := sendMessageResponse{OK: true}
		out, _ := json.Marshal(resp)
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	n := NewTelegramNotifier("abc:123", "555", WithTelegramAPIRoot(srv.URL))
	c.NoError(n.Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	}))

	c.Equal("/botabc:123/sendMessage", capturedPath)
}

func TestTelegramNotifier_LocalhostURL_OmitsInlineButton(t *testing.T) {
	c := require.New(t)

	srv, captured, _ := newTelegramFake(t, true, 0, "")

	n := NewTelegramNotifier("test-bot-token", "555",
		WithTelegramAPIRoot(srv.URL),
	)

	c.NoError(n.Notify(context.Background(), Notification{
		User:           sampleUser(),
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50",
		ApprovalURL:    "http://localhost:8081/ciba/approve?t=abc",
	}))

	// Telegram refuses http://localhost as an inline-button URL; the
	// notifier must drop the keyboard and rely on the auto-linkified
	// URL in the message body instead.
	c.Nil(captured.ReplyMarkup, "http URLs must not produce an inline button")
	c.Contains(captured.Text, "http://localhost:8081/ciba/approve?t=abc",
		"URL must appear in the text body so the user can still tap it")
}

func TestFormatTelegramText_EscapesHTML(t *testing.T) {
	c := require.New(t)
	user := sampleUser()
	text := formatTelegramText(Notification{
		User:           user,
		ClientName:     "<script>alert(1)</script>",
		BindingMessage: "<b>nope</b>",
		ApprovalURL:    "https://op.local",
	})
	c.NotContains(text, "<script>")
	c.NotContains(text, "<b>nope</b>")
	c.Contains(text, "&lt;script&gt;")
	c.Contains(text, "&lt;b&gt;nope&lt;/b&gt;")
}
