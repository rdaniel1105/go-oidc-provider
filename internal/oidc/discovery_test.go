package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDiscoveryDocument_StaticFields(t *testing.T) {
	c := require.New(t)

	doc := NewDiscoveryDocument("http://op.local:8081")

	c.Equal("http://op.local:8081", doc.Issuer)
	c.Equal("http://op.local:8081/oidc/authorize", doc.AuthorizationEndpoint)
	c.Equal("http://op.local:8081/oidc/token", doc.TokenEndpoint)
	c.Equal("http://op.local:8081/oidc/userinfo", doc.UserinfoEndpoint)
	c.Equal("http://op.local:8081/.well-known/jwks.json", doc.JWKSURI)
	c.Equal("http://op.local:8081/oidc/bc-authorize", doc.BackchannelAuthenticationEndpoint)

	c.Contains(doc.ScopesSupported, "openid")
	c.Contains(doc.GrantTypesSupported, "urn:openid:params:grant-type:ciba")
	c.Contains(doc.IDTokenSigningAlgValuesSupported, "ES256")
	c.Contains(doc.CodeChallengeMethodsSupported, "S256")
	c.NotContains(doc.CodeChallengeMethodsSupported, "plain")
	c.Contains(doc.BackchannelTokenDeliveryModesSupported, "poll")
	c.Contains(doc.BackchannelTokenDeliveryModesSupported, "ping")
	c.Contains(doc.BackchannelTokenDeliveryModesSupported, "push")
	c.False(doc.BackchannelUserCodeParameterSupported)
	c.Contains(doc.ACRValuesSupported, "urn:passkey")
}

func TestNewDiscoveryDocument_TrimsTrailingSlash(t *testing.T) {
	c := require.New(t)

	doc := NewDiscoveryDocument("http://op.local:8081/")

	c.Equal("http://op.local:8081", doc.Issuer)
	c.Equal("http://op.local:8081/oidc/token", doc.TokenEndpoint)
}

func TestDiscoveryDocument_JSONShapeMatchesSpec(t *testing.T) {
	c := require.New(t)

	doc := NewDiscoveryDocument("https://op.example.com")
	raw, err := json.Marshal(doc)
	c.NoError(err)

	var asMap map[string]any
	c.NoError(json.Unmarshal(raw, &asMap))

	requiredKeys := []string{
		"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "backchannel_authentication_endpoint",
		"scopes_supported", "response_types_supported", "grant_types_supported",
		"subject_types_supported", "id_token_signing_alg_values_supported",
		"token_endpoint_auth_methods_supported", "code_challenge_methods_supported",
		"acr_values_supported", "claims_supported",
		"backchannel_token_delivery_modes_supported", "backchannel_user_code_parameter_supported",
	}

	for _, k := range requiredKeys {
		c.Contains(asMap, k, "discovery document missing required key %q", k)
	}
}
