package notifier

import (
	"fmt"
	"log/slog"

	"github.com/rdaniel1105/go-oidc-provider/internal/config"
)

// Build returns the AuthDeviceNotifier matching cfg.Notifier. Telegram
// and WhatsApp implementations land in a later phase; until then their
// selection returns an "unimplemented" error so misconfiguration fails
// loudly at boot rather than at first use.
func Build(cfg *config.Config, logger *slog.Logger) (AuthDeviceNotifier, error) {
	switch cfg.Notifier {
	case config.NotifierLog:
		return NewLogNotifier(logger), nil
	case config.NotifierWebhook:
		return NewWebhookNotifier(cfg.WebhookURL), nil
	case config.NotifierTelegram, config.NotifierWhatsApp:
		return nil, fmt.Errorf("notifier: %q is not implemented yet — use NOTIFIER=log or NOTIFIER=webhook", cfg.Notifier)
	default:
		return nil, fmt.Errorf("notifier: unknown notifier %q", cfg.Notifier)
	}
}
