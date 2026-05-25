package oidc

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func sampleClient() *domain.Client {
	return &domain.Client{
		ID:                      uuid.New(),
		ClientID:                "demo-rp",
		RedirectURIs:            []string{"http://op.local:8082/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}
}

func sampleRequest() AuthorizeRequest {
	return AuthorizeRequest{
		ClientID:            "demo-rp",
		RedirectURI:         "http://op.local:8082/callback",
		ResponseType:        "code",
		Scope:               []string{"openid", "profile"},
		State:               "rp-state-xyz",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
	}
}

func TestValidateAuthorizeRequest_HappyPath(t *testing.T) {
	c := require.New(t)
	c.NoError(ValidateAuthorizeRequest(sampleRequest(), sampleClient()))
}

func TestValidateAuthorizeRequest_UnregisteredRedirectURI(t *testing.T) {
	c := require.New(t)
	req := sampleRequest()
	req.RedirectURI = "https://evil.example.com/callback"

	err := ValidateAuthorizeRequest(req, sampleClient())
	ae := AsAuthorizeError(err)
	c.NotNil(ae)
	c.Equal(AuthorizeErrInvalidRequest, ae.Code)
	c.False(ae.SafeRedirect, "must not redirect to an unregistered URI")
}

func TestValidateAuthorizeRequest_GrantNotAllowed(t *testing.T) {
	c := require.New(t)
	client := sampleClient()
	client.GrantTypes = []string{"refresh_token"}

	ae := AsAuthorizeError(ValidateAuthorizeRequest(sampleRequest(), client))
	c.NotNil(ae)
	c.Equal(AuthorizeErrUnauthorizedClient, ae.Code)
	c.True(ae.SafeRedirect)
}

func TestValidateAuthorizeRequest_UnsupportedResponseType(t *testing.T) {
	c := require.New(t)
	req := sampleRequest()
	req.ResponseType = "token"

	ae := AsAuthorizeError(ValidateAuthorizeRequest(req, sampleClient()))
	c.NotNil(ae)
	c.Equal(AuthorizeErrUnsupportedResponseType, ae.Code)
	c.True(ae.SafeRedirect)
}

func TestValidateAuthorizeRequest_ClientResponseTypeRestricted(t *testing.T) {
	c := require.New(t)
	client := sampleClient()
	client.ResponseTypes = []string{"id_token"}

	ae := AsAuthorizeError(ValidateAuthorizeRequest(sampleRequest(), client))
	c.NotNil(ae)
	c.Equal(AuthorizeErrUnauthorizedClient, ae.Code)
	c.True(ae.SafeRedirect)
}

func TestValidateAuthorizeRequest_MissingPKCE(t *testing.T) {
	c := require.New(t)
	req := sampleRequest()
	req.CodeChallenge = ""

	ae := AsAuthorizeError(ValidateAuthorizeRequest(req, sampleClient()))
	c.NotNil(ae)
	c.Equal(AuthorizeErrInvalidRequest, ae.Code)
	c.True(ae.SafeRedirect)
}

func TestValidateAuthorizeRequest_PKCEMethodMustBeS256(t *testing.T) {
	c := require.New(t)
	req := sampleRequest()
	req.CodeChallengeMethod = "plain"

	ae := AsAuthorizeError(ValidateAuthorizeRequest(req, sampleClient()))
	c.NotNil(ae)
	c.Equal(AuthorizeErrInvalidRequest, ae.Code)
}

func TestValidateAuthorizeRequest_ScopeMissingOpenID(t *testing.T) {
	c := require.New(t)
	req := sampleRequest()
	req.Scope = []string{"profile"}

	ae := AsAuthorizeError(ValidateAuthorizeRequest(req, sampleClient()))
	c.NotNil(ae)
	c.Equal(AuthorizeErrInvalidScope, ae.Code)
}

func TestValidateAuthorizeRequest_ScopeNotAllowedForClient(t *testing.T) {
	c := require.New(t)
	req := sampleRequest()
	req.Scope = []string{"openid", "payment"}

	ae := AsAuthorizeError(ValidateAuthorizeRequest(req, sampleClient()))
	c.NotNil(ae)
	c.Equal(AuthorizeErrInvalidScope, ae.Code)
}

func TestAuthorizeError_String(t *testing.T) {
	c := require.New(t)
	e := &AuthorizeError{Code: AuthorizeErrInvalidScope, Description: "scope X not allowed"}
	c.Contains(e.Error(), "invalid_scope")
	c.Contains(e.Error(), "scope X not allowed")

	bare := &AuthorizeError{Code: AuthorizeErrServerError}
	c.Contains(bare.Error(), "server_error")
}
