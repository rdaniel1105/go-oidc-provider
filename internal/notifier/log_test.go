package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleUser() *domain.OPUser {
	phone := "+573001234567"
	return &domain.OPUser{
		ID:          uuid.New(),
		Email:       "alice@example.com",
		DisplayName: "Alice",
		PhoneE164:   &phone,
	}
}

func TestLogNotifier_Notify_WritesEveryField(t *testing.T) {
	c := require.New(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	n := NewLogNotifier(logger)

	user := sampleUser()
	c.NoError(n.Notify(context.Background(), Notification{
		User:           user,
		ClientName:     "Demo RP",
		BindingMessage: "Authorize $50 to Café Acme",
		ApprovalURL:    "https://op.local:8081/ciba/approve?t=abc",
	}))

	// One JSON line per slog call; parse it and check the fields.
	line := strings.TrimSpace(buf.String())
	c.NotEmpty(line)

	var parsed map[string]any
	c.NoError(json.Unmarshal([]byte(line), &parsed))
	c.Equal(user.ID.String(), parsed["op_user_id"])
	c.Equal("alice@example.com", parsed["email"])
	c.Equal("Demo RP", parsed["client_name"])
	c.Equal("Authorize $50 to Café Acme", parsed["binding_message"])
	c.Equal("https://op.local:8081/ciba/approve?t=abc", parsed["approval_url"])
}
