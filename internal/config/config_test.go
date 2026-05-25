package config

import (
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func baseEnv() map[string]string {
	return map[string]string{
		"HTTP_ADDR":           ":8081",
		"ISSUER":              "http://op.local:8081",
		"DATABASE_URL":        "postgres://u:p@h/d",
		"REDIS_URL":           "redis://r:6379/0",
		"KEYS_DIR":            "/var/lib/op/keys",
		"PASSKEY_SERVICE_URL": "http://passkey:8080",
		"NOTIFIER":            "log",
		"AUTH_CODE_TTL":       "5m",
		"CIBA_REQUEST_TTL":    "10m",
		"APPROVAL_TOKEN_TTL":  "5m",
		"ACCESS_TOKEN_TTL":    "1h",
		"REFRESH_TOKEN_TTL":   "720h",
	}
}

func TestLoad_AllValid(t *testing.T) {
	c := require.New(t)

	withEnv(t, baseEnv())

	cfg, err := Load()
	c.NoError(err)
	c.Equal(":8081", cfg.HTTPAddr)
	c.Equal("http://op.local:8081", cfg.Issuer)
	c.Equal(NotifierLog, cfg.Notifier)
	c.Equal(5*time.Minute, cfg.AuthCodeTTL)
	c.Equal(10*time.Minute, cfg.CIBARequestTTL)
	c.Equal(5*time.Minute, cfg.ApprovalTokenTTL)
	c.Equal(time.Hour, cfg.AccessTokenTTL)
	c.Equal(720*time.Hour, cfg.RefreshTokenTTL)
}

func TestLoad_NotifierDefaultsToLog(t *testing.T) {
	c := require.New(t)

	env := baseEnv()
	env["NOTIFIER"] = ""
	withEnv(t, env)

	cfg, err := Load()
	c.NoError(err)
	c.Equal(NotifierLog, cfg.Notifier)
}

func TestLoad_MissingRequired(t *testing.T) {
	cases := []struct {
		drop string
		want error
	}{
		{"HTTP_ADDR", ErrMissingHTTPAddr},
		{"ISSUER", ErrMissingIssuer},
		{"DATABASE_URL", ErrMissingDatabaseURL},
		{"REDIS_URL", ErrMissingRedisURL},
		{"KEYS_DIR", ErrMissingKeysDir},
		{"PASSKEY_SERVICE_URL", ErrMissingPasskeyServiceURL},
	}

	for _, tc := range cases {
		t.Run(tc.drop, func(t *testing.T) {
			c := require.New(t)

			env := copyMap(baseEnv())
			env[tc.drop] = ""
			withEnv(t, env)

			_, err := Load()
			c.ErrorIs(err, tc.want)
		})
	}
}

func TestLoad_InvalidTTLs(t *testing.T) {
	cases := []struct {
		key     string
		bad     string
		sentinel error
	}{
		{"AUTH_CODE_TTL", "nope", ErrInvalidAuthCodeTTL},
		{"AUTH_CODE_TTL", "-1s", ErrInvalidAuthCodeTTL},
		{"CIBA_REQUEST_TTL", "", ErrInvalidCIBARequestTTL},
		{"APPROVAL_TOKEN_TTL", "0s", ErrInvalidApprovalTokenTTL},
		{"ACCESS_TOKEN_TTL", "twenty", ErrInvalidAccessTokenTTL},
		{"REFRESH_TOKEN_TTL", "-720h", ErrInvalidRefreshTokenTTL},
	}

	for _, tc := range cases {
		t.Run(tc.key+"="+tc.bad, func(t *testing.T) {
			c := require.New(t)

			env := copyMap(baseEnv())
			env[tc.key] = tc.bad
			withEnv(t, env)

			_, err := Load()
			c.ErrorIs(err, tc.sentinel)
		})
	}
}

func TestLoad_UnknownNotifier(t *testing.T) {
	c := require.New(t)

	env := copyMap(baseEnv())
	env["NOTIFIER"] = "carrierpigeon"
	withEnv(t, env)

	_, err := Load()
	c.ErrorIs(err, ErrUnknownNotifier)
}

func TestLoad_TelegramNotifier(t *testing.T) {
	c := require.New(t)

	env := copyMap(baseEnv())
	env["NOTIFIER"] = "telegram"
	env["TELEGRAM_BOT_TOKEN"] = "123:abc"
	env["TELEGRAM_DEFAULT_CHAT_ID"] = "555"
	withEnv(t, env)

	cfg, err := Load()
	c.NoError(err)
	c.Equal(NotifierTelegram, cfg.Notifier)
	c.Equal("123:abc", cfg.TelegramBotToken)
	c.Equal("555", cfg.TelegramDefaultChatID)
}

func TestLoad_TelegramMissingCreds(t *testing.T) {
	cases := []struct {
		missing string
		want    error
	}{
		{"TELEGRAM_BOT_TOKEN", ErrMissingTelegramBotToken},
		{"TELEGRAM_DEFAULT_CHAT_ID", ErrMissingTelegramChatID},
	}

	for _, tc := range cases {
		t.Run(tc.missing, func(t *testing.T) {
			c := require.New(t)

			env := copyMap(baseEnv())
			env["NOTIFIER"] = "telegram"
			env["TELEGRAM_BOT_TOKEN"] = "123:abc"
			env["TELEGRAM_DEFAULT_CHAT_ID"] = "555"
			env[tc.missing] = ""
			withEnv(t, env)

			_, err := Load()
			c.ErrorIs(err, tc.want)
		})
	}
}

func TestLoad_WhatsAppMissingCreds(t *testing.T) {
	cases := []struct {
		missing string
		want    error
	}{
		{"WHATSAPP_PHONE_NUMBER_ID", ErrMissingWhatsAppPhoneID},
		{"WHATSAPP_ACCESS_TOKEN", ErrMissingWhatsAppToken},
		{"WHATSAPP_TEMPLATE_NAME", ErrMissingWhatsAppTemplate},
	}

	for _, tc := range cases {
		t.Run(tc.missing, func(t *testing.T) {
			c := require.New(t)

			env := copyMap(baseEnv())
			env["NOTIFIER"] = "whatsapp"
			env["WHATSAPP_PHONE_NUMBER_ID"] = "1234567890"
			env["WHATSAPP_ACCESS_TOKEN"] = "EAAG..."
			env["WHATSAPP_TEMPLATE_NAME"] = "ciba_approval"
			env[tc.missing] = ""
			withEnv(t, env)

			_, err := Load()
			c.ErrorIs(err, tc.want)
		})
	}
}

func TestLoad_WebhookMissingURL(t *testing.T) {
	c := require.New(t)

	env := copyMap(baseEnv())
	env["NOTIFIER"] = "webhook"
	withEnv(t, env)

	_, err := Load()
	c.ErrorIs(err, ErrMissingWebhookURL)
}

func withEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	maps.Copy(out, m)
	return out
}
