package notifier

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBuild_Log(t *testing.T) {
	c := require.New(t)
	n, err := Build(&config.Config{Notifier: config.NotifierLog}, discardLogger())
	c.NoError(err)

	_, ok := n.(*LogNotifier)
	c.True(ok)
}

func TestBuild_Webhook(t *testing.T) {
	c := require.New(t)
	n, err := Build(&config.Config{
		Notifier:   config.NotifierWebhook,
		WebhookURL: "https://hooks.example.com/notify",
	}, discardLogger())
	c.NoError(err)

	_, ok := n.(*WebhookNotifier)
	c.True(ok)
}

func TestBuild_Telegram(t *testing.T) {
	c := require.New(t)
	n, err := Build(&config.Config{
		Notifier:              config.NotifierTelegram,
		TelegramBotToken:      "abc:123",
		TelegramDefaultChatID: "555",
	}, discardLogger())
	c.NoError(err)

	_, ok := n.(*TelegramNotifier)
	c.True(ok)
}

func TestBuild_WhatsAppUnimplemented(t *testing.T) {
	c := require.New(t)
	_, err := Build(&config.Config{Notifier: config.NotifierWhatsApp}, discardLogger())
	c.Error(err, "whatsapp should fail until its implementation lands")
}

func TestBuild_Unknown(t *testing.T) {
	c := require.New(t)
	_, err := Build(&config.Config{Notifier: config.NotifierKind("smoke-signal")}, discardLogger())
	c.Error(err)
}
