package domain

import (
	"time"

	"github.com/google/uuid"
)

// TokenEndpointAuthMethod names a client authentication scheme accepted at
// the token endpoint. The enum is intentionally narrow.
type TokenEndpointAuthMethod string

const (
	// AuthMethodClientSecretBasic uses HTTP Basic with client_id:client_secret.
	AuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	// AuthMethodClientSecretPost passes client_id and client_secret in the
	// request body.
	AuthMethodClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	// AuthMethodNone is used by public clients (e.g. SPAs) that rely on
	// PKCE for protection instead of a shared secret.
	AuthMethodNone TokenEndpointAuthMethod = "none"
)

// CIBADeliveryMode names how the OP returns tokens to the RP for a CIBA
// flow. Per the spec, exactly one mode is configured per client.
type CIBADeliveryMode string

const (
	// CIBADeliveryPoll has the RP poll the token endpoint until the
	// authorization completes.
	CIBADeliveryPoll CIBADeliveryMode = "poll"
	// CIBADeliveryPing has the OP notify the RP via POST to the client
	// notification endpoint; the RP then collects tokens from the token
	// endpoint.
	CIBADeliveryPing CIBADeliveryMode = "ping"
	// CIBADeliveryPush has the OP deliver tokens directly to the client
	// notification endpoint without a polling round-trip.
	CIBADeliveryPush CIBADeliveryMode = "push"
)

// Client is an OAuth/OIDC relying party registered with the OP. Clients are
// loaded from a YAML file at startup and reconciled into the clients table;
// see the YAML configuration documentation for the source-of-truth format.
type Client struct {
	// ID is the internal row identifier. Not exposed to RPs.
	ID uuid.UUID
	// ClientID is the public OAuth client identifier.
	ClientID string
	// ClientSecretHash is the bcrypt hash of the client secret. Nil for
	// public clients using AuthMethodNone.
	ClientSecretHash *string
	// RedirectURIs is the allow-list of redirect_uri values accepted by
	// /oidc/authorize.
	RedirectURIs []string
	// GrantTypes lists the OAuth grant_type values the client may use at
	// /oidc/token.
	GrantTypes []string
	// ResponseTypes lists the OAuth response_type values the client may
	// request at /oidc/authorize.
	ResponseTypes []string
	// Scopes lists the scope values the client may request.
	Scopes []string
	// TokenEndpointAuthMethod names the client authentication scheme.
	TokenEndpointAuthMethod TokenEndpointAuthMethod
	// ClientNotificationEndpoint is the URL the OP POSTs CIBA ping/push
	// payloads to. Nil for non-CIBA clients or CIBA clients using poll.
	ClientNotificationEndpoint *string
	// BackchannelTokenDeliveryMode is the CIBA delivery mode. Nil for
	// non-CIBA clients.
	BackchannelTokenDeliveryMode *CIBADeliveryMode
	// CreatedAt is the row creation timestamp.
	CreatedAt time.Time
	// UpdatedAt is the last-modification timestamp; refreshed by the YAML
	// reconciler on every field-changing update.
	UpdatedAt time.Time
}
