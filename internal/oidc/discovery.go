package oidc

import "strings"

// DiscoveryDocument is the OpenID Provider configuration metadata served at
// /.well-known/openid-configuration. The shape follows OIDC Discovery 1.0
// plus the CIBA extension fields; only the entries this OP actually supports
// are populated, which keeps the contract honest for RPs that introspect it.
type DiscoveryDocument struct {
	// Issuer is the canonical URL identifier of this OP. It MUST exactly
	// match the `iss` claim in issued ID tokens.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is the URL of the OAuth 2.0 authorization
	// endpoint serving the auth-code + PKCE flow.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is the URL of the OAuth 2.0 token endpoint serving
	// authorization_code, refresh_token, and CIBA grants.
	TokenEndpoint string `json:"token_endpoint"`
	// UserinfoEndpoint is the URL of the Bearer-protected UserInfo endpoint.
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	// JWKSURI is the URL of the JSON Web Key Set document.
	JWKSURI string `json:"jwks_uri"`
	// BackchannelAuthenticationEndpoint is the URL of the CIBA backchannel
	// authentication endpoint (`POST /oidc/bc-authorize`).
	BackchannelAuthenticationEndpoint string `json:"backchannel_authentication_endpoint"`

	// ScopesSupported lists every scope value the OP accepts.
	ScopesSupported []string `json:"scopes_supported"`
	// ResponseTypesSupported lists the OAuth response_type values supported
	// at the authorization endpoint.
	ResponseTypesSupported []string `json:"response_types_supported"`
	// GrantTypesSupported lists the OAuth grant_type values supported at
	// the token endpoint.
	GrantTypesSupported []string `json:"grant_types_supported"`
	// SubjectTypesSupported lists the OIDC `subject_type` values supported.
	// This OP issues a single public sub per op_user.
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// IDTokenSigningAlgValuesSupported lists the JWS algs used to sign ID tokens.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// TokenEndpointAuthMethodsSupported lists how clients may authenticate
	// at the token endpoint.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// CodeChallengeMethodsSupported lists supported PKCE methods. S256 only;
	// `plain` is intentionally excluded.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// ACRValuesSupported lists the `acr` values an RP may request.
	ACRValuesSupported []string `json:"acr_values_supported"`
	// ClaimsSupported lists the claims this OP may issue in ID tokens or at UserInfo.
	ClaimsSupported []string `json:"claims_supported"`

	// BackchannelTokenDeliveryModesSupported lists CIBA delivery modes the OP supports.
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported"`
	// BackchannelUserCodeParameterSupported reports whether the CIBA
	// `user_code` parameter is honored. This OP does not implement it.
	BackchannelUserCodeParameterSupported bool `json:"backchannel_user_code_parameter_supported"`
}

// NewDiscoveryDocument builds the static OpenID Provider configuration for
// the given issuer URL. Endpoint paths are appended to the issuer; a trailing
// slash on the issuer is tolerated.
func NewDiscoveryDocument(issuer string) DiscoveryDocument {
	base := strings.TrimRight(issuer, "/")

	return DiscoveryDocument{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/oidc/authorize",
		TokenEndpoint:                     base + "/oidc/token",
		UserinfoEndpoint:                  base + "/oidc/userinfo",
		JWKSURI:                           base + "/.well-known/jwks.json",
		BackchannelAuthenticationEndpoint: base + "/oidc/bc-authorize",

		ScopesSupported:        []string{"openid", "profile", "email"},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"urn:openid:params:grant-type:ciba",
		},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ACRValuesSupported:                []string{"urn:passkey"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time",
			"nonce", "acr", "amr",
			"email", "email_verified",
			"name", "preferred_username",
		},

		BackchannelTokenDeliveryModesSupported: []string{"poll", "ping", "push"},
		BackchannelUserCodeParameterSupported:  false,
	}
}
