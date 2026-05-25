package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"
)

// telegramAPIRoot is the base URL of the Telegram Bot API. Overridable
// in tests via the constructor option.
const telegramAPIRoot = "https://api.telegram.org"

// Sentinel errors returned by TelegramNotifier.
var (
	// ErrTelegramAPI is returned when the Telegram Bot API responds with
	// ok=false (anything from a bad chat_id to a missing bot token).
	ErrTelegramAPI = errors.New("notifier: telegram api error")
)

// TelegramNotifier delivers the approval link as a Telegram message with
// an inline-keyboard button that opens the URL when tapped. Setup is the
// 90-second demo path: create a bot via @BotFather, paste the token in
// TELEGRAM_BOT_TOKEN, send /start to your bot once so it can DM you, and
// put your chat id in TELEGRAM_DEFAULT_CHAT_ID.
//
// Per-user chat routing is a stretch goal: today every notification is
// sent to the default chat id. For the demo this is the developer's own
// chat; for a multi-user deployment, add a per-user chat-id binding
// (e.g. an op_users.telegram_chat_id column) and read it from the
// Notification.User row instead.
type TelegramNotifier struct {
	apiRoot       string
	botToken      string
	defaultChatID string
	http          *http.Client
}

// TelegramOption customizes a TelegramNotifier.
type TelegramOption func(*TelegramNotifier)

// WithTelegramHTTPClient overrides the default *http.Client. Useful for
// custom timeouts, transport, or test fakes.
func WithTelegramHTTPClient(c *http.Client) TelegramOption {
	return func(n *TelegramNotifier) { n.http = c }
}

// WithTelegramAPIRoot overrides the Telegram Bot API base URL. Tests
// point this at an httptest server.
func WithTelegramAPIRoot(root string) TelegramOption {
	return func(n *TelegramNotifier) { n.apiRoot = root }
}

// NewTelegramNotifier returns a TelegramNotifier targeting the official
// Telegram Bot API and the given default chat id.
func NewTelegramNotifier(botToken, defaultChatID string, opts ...TelegramOption) *TelegramNotifier {
	n := &TelegramNotifier{
		apiRoot:       telegramAPIRoot,
		botToken:      botToken,
		defaultChatID: defaultChatID,
		http:          &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// inlineKeyboardButton is one button in a Telegram inline-keyboard row.
type inlineKeyboardButton struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

// inlineKeyboardMarkup is the reply_markup payload for inline keyboards.
type inlineKeyboardMarkup struct {
	InlineKeyboard [][]inlineKeyboardButton `json:"inline_keyboard"`
}

// sendMessageRequest is the body for Telegram's sendMessage method.
// ReplyMarkup is omitted when nil so the OP can send a plain-text
// fallback for URLs Telegram would reject as inline buttons (notably
// http://localhost during local development).
type sendMessageRequest struct {
	ChatID      string                `json:"chat_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode"`
	ReplyMarkup *inlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

// sendMessageResponse is the envelope every Telegram API response uses.
type sendMessageResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	ErrorCode   int    `json:"error_code"`
}

// Notify sends the approval URL to the configured chat id as a Telegram
// message with an inline "Authorize" button when the URL is HTTPS, or
// the URL inline in the message body for non-HTTPS URLs (Telegram's API
// refuses non-HTTPS inline-button URLs, including http://localhost). The
// URL is always present in the text body too so the user can click /
// copy it even when the button is omitted.
func (n *TelegramNotifier) Notify(ctx context.Context, in Notification) error {
	req := sendMessageRequest{
		ChatID:    n.defaultChatID,
		Text:      formatTelegramText(in),
		ParseMode: "HTML",
	}
	if strings.HasPrefix(in.ApprovalURL, "https://") {
		req.ReplyMarkup = &inlineKeyboardMarkup{
			InlineKeyboard: [][]inlineKeyboardButton{
				{
					{Text: "Authorize", URL: in.ApprovalURL},
				},
			},
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("notifier: marshal telegram body: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/sendMessage", n.apiRoot, n.botToken)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notifier: build telegram request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := n.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("notifier: telegram POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("notifier: read telegram response: %w", err)
	}

	var decoded sendMessageResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("notifier: decode telegram response: %w", err)
	}

	if !decoded.OK {
		return fmt.Errorf("%w: %d %s", ErrTelegramAPI, decoded.ErrorCode, decoded.Description)
	}

	return nil
}

// formatTelegramText composes the human-readable body of the Telegram
// message. parse_mode=HTML lets us bold the binding message and
// italicize the RP name; the approval URL appears at the bottom so
// Telegram's auto-linkification makes it tappable even when the inline
// button is omitted (the button is only added for https URLs).
func formatTelegramText(in Notification) string {
	return fmt.Sprintf(
		"<b>Authorization request</b>\nFrom: <i>%s</i>\n\n%s\n\n%s",
		html.EscapeString(in.ClientName),
		html.EscapeString(in.BindingMessage),
		html.EscapeString(in.ApprovalURL),
	)
}
