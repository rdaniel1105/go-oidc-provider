package notifier

import (
	"context"
	"log/slog"
)

// LogNotifier writes the approval URL to the configured slog handler.
// It is the zero-config default — useful for tests, CI, and the demo
// flow before a real channel (Telegram, WhatsApp) is wired up. The
// reviewer cloning the repo sees the URL in `docker compose logs op`
// and can click through without setting up any external service.
type LogNotifier struct {
	logger *slog.Logger
}

// NewLogNotifier returns a LogNotifier that writes to the given logger.
func NewLogNotifier(logger *slog.Logger) *LogNotifier {
	return &LogNotifier{logger: logger}
}

// Notify writes one structured log line at INFO level containing the
// approval URL plus enough identifying detail to correlate with the
// /bc-authorize call. Returns nil unconditionally — stdout doesn't fail
// in any meaningful way here, so the CIBA flow can rely on the log
// notifier as a "won't surprise you" default.
func (n *LogNotifier) Notify(ctx context.Context, in Notification) error {
	n.logger.LogAttrs(ctx, slog.LevelInfo, "auth-device notification (log notifier)",
		slog.String("op_user_id", in.User.ID.String()),
		slog.String("email", in.User.Email),
		slog.String("client_name", in.ClientName),
		slog.String("binding_message", in.BindingMessage),
		slog.String("approval_url", in.ApprovalURL),
	)
	return nil
}
