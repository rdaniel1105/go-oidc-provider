// Package config loads service configuration from environment variables.
//
// Local development reads a `.env` file via godotenv when present. In Docker
// and production the variables come from the real environment; the .env load
// silently no-ops if the file is absent.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// NotifierKind identifies which AuthDeviceNotifier implementation the OP
// should use to deliver the CIBA approval link to the user's device.
type NotifierKind string

const (
	// NotifierLog writes the approval URL to stdout. Zero-config default;
	// useful for tests and local demos where no real channel is available.
	NotifierLog NotifierKind = "log"
	// NotifierTelegram delivers the approval URL via the Telegram Bot API
	// as an inline-keyboard message.
	NotifierTelegram NotifierKind = "telegram"
	// NotifierWhatsApp delivers the approval URL via the Meta Cloud API
	// using an approved template message.
	NotifierWhatsApp NotifierKind = "whatsapp"
	// NotifierWebhook POSTs the approval payload to a configured URL.
	// Intended for native-app integrations (Auth0-Guardian-style).
	NotifierWebhook NotifierKind = "webhook"
)

// Sentinel errors returned by Load when a required variable is missing or
// invalid. Callers can match with errors.Is to react to specific
// misconfigurations.
var (
	// ErrMissingHTTPAddr is returned when HTTP_ADDR is empty.
	ErrMissingHTTPAddr = errors.New("HTTP_ADDR is required")
	// ErrMissingIssuer is returned when ISSUER is empty.
	ErrMissingIssuer = errors.New("ISSUER is required")
	// ErrMissingDatabaseURL is returned when DATABASE_URL is empty.
	ErrMissingDatabaseURL = errors.New("DATABASE_URL is required")
	// ErrMissingRedisURL is returned when REDIS_URL is empty.
	ErrMissingRedisURL = errors.New("REDIS_URL is required")
	// ErrMissingKeysDir is returned when KEYS_DIR is empty.
	ErrMissingKeysDir = errors.New("KEYS_DIR is required")
	// ErrMissingPasskeyServiceURL is returned when PASSKEY_SERVICE_URL is empty.
	ErrMissingPasskeyServiceURL = errors.New("PASSKEY_SERVICE_URL is required")
	// ErrUnknownNotifier is returned when NOTIFIER is set to an unrecognized value.
	ErrUnknownNotifier = errors.New("NOTIFIER must be one of: log, telegram, whatsapp, webhook")
	// ErrMissingTelegramBotToken is returned when NOTIFIER=telegram but
	// TELEGRAM_BOT_TOKEN is empty.
	ErrMissingTelegramBotToken = errors.New("TELEGRAM_BOT_TOKEN is required when NOTIFIER=telegram")
	// ErrMissingTelegramChatID is returned when NOTIFIER=telegram but
	// TELEGRAM_DEFAULT_CHAT_ID is empty.
	ErrMissingTelegramChatID = errors.New("TELEGRAM_DEFAULT_CHAT_ID is required when NOTIFIER=telegram")
	// ErrMissingWhatsAppPhoneID is returned when NOTIFIER=whatsapp but
	// WHATSAPP_PHONE_NUMBER_ID is empty.
	ErrMissingWhatsAppPhoneID = errors.New("WHATSAPP_PHONE_NUMBER_ID is required when NOTIFIER=whatsapp")
	// ErrMissingWhatsAppToken is returned when NOTIFIER=whatsapp but
	// WHATSAPP_ACCESS_TOKEN is empty.
	ErrMissingWhatsAppToken = errors.New("WHATSAPP_ACCESS_TOKEN is required when NOTIFIER=whatsapp")
	// ErrMissingWhatsAppTemplate is returned when NOTIFIER=whatsapp but
	// WHATSAPP_TEMPLATE_NAME is empty.
	ErrMissingWhatsAppTemplate = errors.New("WHATSAPP_TEMPLATE_NAME is required when NOTIFIER=whatsapp")
	// ErrMissingWebhookURL is returned when NOTIFIER=webhook but WEBHOOK_URL is empty.
	ErrMissingWebhookURL = errors.New("WEBHOOK_URL is required when NOTIFIER=webhook")
	// ErrInvalidAuthCodeTTL is returned when AUTH_CODE_TTL is missing, malformed,
	// or non-positive (e.g. "5m").
	ErrInvalidAuthCodeTTL = errors.New("AUTH_CODE_TTL must be a positive Go duration")
	// ErrInvalidCIBARequestTTL is returned when CIBA_REQUEST_TTL is missing,
	// malformed, or non-positive (e.g. "10m").
	ErrInvalidCIBARequestTTL = errors.New("CIBA_REQUEST_TTL must be a positive Go duration")
	// ErrInvalidApprovalTokenTTL is returned when APPROVAL_TOKEN_TTL is missing,
	// malformed, or non-positive (e.g. "5m").
	ErrInvalidApprovalTokenTTL = errors.New("APPROVAL_TOKEN_TTL must be a positive Go duration")
	// ErrInvalidAccessTokenTTL is returned when ACCESS_TOKEN_TTL is missing,
	// malformed, or non-positive (e.g. "1h").
	ErrInvalidAccessTokenTTL = errors.New("ACCESS_TOKEN_TTL must be a positive Go duration")
	// ErrInvalidRefreshTokenTTL is returned when REFRESH_TOKEN_TTL is missing,
	// malformed, or non-positive (e.g. "720h").
	ErrInvalidRefreshTokenTTL = errors.New("REFRESH_TOKEN_TTL must be a positive Go duration")
)

// Config holds the runtime configuration for the OIDC provider. Values are
// populated by Load from environment variables and validated before use.
type Config struct {
	// HTTPAddr is the address the HTTP server binds to (e.g. ":8081").
	HTTPAddr string
	// Issuer is the canonical URL of this OP, used as the `iss` claim in
	// every issued ID token and the base of the discovery document
	// (e.g. "http://op.local:8081").
	Issuer string
	// DatabaseURL is the Postgres connection string used by the client,
	// op_user, and refresh_token stores.
	DatabaseURL string
	// RedisURL is the Redis connection string used for short-lived state
	// (auth codes, CIBA requests, approval tokens).
	RedisURL string
	// KeysDir is the directory where ES256 signing keys are persisted. The
	// directory is created on first boot if missing and an initial key is
	// generated when none are found.
	KeysDir string
	// PasskeyServiceURL is the base URL of the go-passkey-auth service this
	// OP delegates WebAuthn ceremonies to (e.g. "http://passkey:8080").
	PasskeyServiceURL string

	// Notifier selects which AuthDeviceNotifier implementation delivers the
	// CIBA approval link to the user's device.
	Notifier NotifierKind

	// TelegramBotToken is the bot token issued by @BotFather. Only consulted
	// when Notifier == NotifierTelegram.
	TelegramBotToken string
	// TelegramDefaultChatID is the fallback chat ID used when no user-specific
	// chat binding is on file. Only consulted when Notifier == NotifierTelegram.
	TelegramDefaultChatID string

	// WhatsAppPhoneNumberID is the Meta Cloud API phone-number ID that owns
	// the sender identity. Only consulted when Notifier == NotifierWhatsApp.
	WhatsAppPhoneNumberID string
	// WhatsAppAccessToken is the bearer token for the Meta Cloud API. Only
	// consulted when Notifier == NotifierWhatsApp.
	WhatsAppAccessToken string
	// WhatsAppTemplateName is the approved template message used to deliver
	// the approval link. Only consulted when Notifier == NotifierWhatsApp.
	WhatsAppTemplateName string

	// WebhookURL is the destination for generic webhook delivery. Only
	// consulted when Notifier == NotifierWebhook.
	WebhookURL string

	// AuthCodeTTL bounds how long an authorization code is redeemable at
	// the token endpoint after being issued at /oidc/authorize.
	AuthCodeTTL time.Duration
	// CIBARequestTTL bounds how long a backchannel authentication request
	// can stay pending before expiring (`expired_token` at /oidc/token).
	CIBARequestTTL time.Duration
	// ApprovalTokenTTL bounds how long the URL-safe approval link in the
	// notifier message remains usable.
	ApprovalTokenTTL time.Duration
	// AccessTokenTTL is the lifetime of an access token / ID token pair.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the lifetime of a refresh token before forced
	// re-authentication.
	RefreshTokenTTL time.Duration
}

// Load reads configuration from the environment. A `.env` file at the working
// directory is loaded first if present; existing env vars are not overridden.
func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		HTTPAddr:              os.Getenv("HTTP_ADDR"),
		Issuer:                os.Getenv("ISSUER"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		RedisURL:              os.Getenv("REDIS_URL"),
		KeysDir:               os.Getenv("KEYS_DIR"),
		PasskeyServiceURL:     os.Getenv("PASSKEY_SERVICE_URL"),
		Notifier:              notifierFromEnv(os.Getenv("NOTIFIER")),
		TelegramBotToken:      os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramDefaultChatID: os.Getenv("TELEGRAM_DEFAULT_CHAT_ID"),
		WhatsAppPhoneNumberID: os.Getenv("WHATSAPP_PHONE_NUMBER_ID"),
		WhatsAppAccessToken:   os.Getenv("WHATSAPP_ACCESS_TOKEN"),
		WhatsAppTemplateName:  os.Getenv("WHATSAPP_TEMPLATE_NAME"),
		WebhookURL:            os.Getenv("WEBHOOK_URL"),
	}

	ttls := []struct {
		envKey   string
		target   *time.Duration
		sentinel error
	}{
		{"AUTH_CODE_TTL", &cfg.AuthCodeTTL, ErrInvalidAuthCodeTTL},
		{"CIBA_REQUEST_TTL", &cfg.CIBARequestTTL, ErrInvalidCIBARequestTTL},
		{"APPROVAL_TOKEN_TTL", &cfg.ApprovalTokenTTL, ErrInvalidApprovalTokenTTL},
		{"ACCESS_TOKEN_TTL", &cfg.AccessTokenTTL, ErrInvalidAccessTokenTTL},
		{"REFRESH_TOKEN_TTL", &cfg.RefreshTokenTTL, ErrInvalidRefreshTokenTTL},
	}

	for _, t := range ttls {
		d, err := parseDuration(os.Getenv(t.envKey), t.sentinel)
		if err != nil {
			return nil, err
		}

		*t.target = d
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	switch {
	case c.HTTPAddr == "":
		return ErrMissingHTTPAddr
	case c.Issuer == "":
		return ErrMissingIssuer
	case c.DatabaseURL == "":
		return ErrMissingDatabaseURL
	case c.RedisURL == "":
		return ErrMissingRedisURL
	case c.KeysDir == "":
		return ErrMissingKeysDir
	case c.PasskeyServiceURL == "":
		return ErrMissingPasskeyServiceURL
	}

	return c.validateNotifier()
}

func (c *Config) validateNotifier() error {
	switch c.Notifier {
	case NotifierLog:
		return nil
	case NotifierTelegram:
		if c.TelegramBotToken == "" {
			return ErrMissingTelegramBotToken
		}

		if c.TelegramDefaultChatID == "" {
			return ErrMissingTelegramChatID
		}

		return nil
	case NotifierWhatsApp:
		if c.WhatsAppPhoneNumberID == "" {
			return ErrMissingWhatsAppPhoneID
		}

		if c.WhatsAppAccessToken == "" {
			return ErrMissingWhatsAppToken
		}

		if c.WhatsAppTemplateName == "" {
			return ErrMissingWhatsAppTemplate
		}

		return nil
	case NotifierWebhook:
		if c.WebhookURL == "" {
			return ErrMissingWebhookURL
		}

		return nil
	default:
		return ErrUnknownNotifier
	}
}

// notifierFromEnv maps the NOTIFIER env value to a NotifierKind. An empty
// value defaults to NotifierLog (zero-config local development). Any other
// unknown value is preserved so validate can reject it with ErrUnknownNotifier.
func notifierFromEnv(raw string) NotifierKind {
	if raw == "" {
		return NotifierLog
	}

	switch n := NotifierKind(raw); n {
	case NotifierLog, NotifierTelegram, NotifierWhatsApp, NotifierWebhook:
		return n
	default:
		return NotifierKind(raw)
	}
}

func parseDuration(raw string, sentinel error) (time.Duration, error) {
	if raw == "" {
		return 0, sentinel
	}

	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%w: %q", sentinel, raw)
	}

	return d, nil
}
