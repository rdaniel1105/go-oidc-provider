package oidc

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
)

func cibaSampleClient() *domain.Client {
	return &domain.Client{
		ID:           uuid.New(),
		ClientID:     "demo-rp",
		RedirectURIs: []string{"http://op.local:8082/callback"},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			CIBAGrantType,
		},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "payment"},
		TokenEndpointAuthMethod: domain.AuthMethodClientSecretBasic,
	}
}

func cibaSampleRequest() BCAuthorizeRequest {
	return BCAuthorizeRequest{
		ClientID:                "demo-rp",
		Scope:                   []string{"openid", "payment"},
		LoginHint:               "alice@example.com",
		BindingMessage:          "Authorize $50 to Café Acme",
		ACRValues:               []string{"urn:passkey"},
		ClientNotificationToken: "rp-correlation-id",
		RequestedExpiry:         300,
	}
}

func TestValidateBCAuthorizeRequest_HappyPath(t *testing.T) {
	c := require.New(t)
	c.NoError(ValidateBCAuthorizeRequest(cibaSampleRequest(), cibaSampleClient()))
}

func TestValidateBCAuthorizeRequest_ClientNotAllowedCIBA(t *testing.T) {
	c := require.New(t)
	client := cibaSampleClient()
	client.GrantTypes = []string{"authorization_code"}

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(cibaSampleRequest(), client))
	c.True(ok)
	c.Equal(BCErrUnauthorizedClient, bae.Code)
}

func TestValidateBCAuthorizeRequest_MissingLoginHint(t *testing.T) {
	c := require.New(t)
	req := cibaSampleRequest()
	req.LoginHint = "   "

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, cibaSampleClient()))
	c.True(ok)
	c.Equal(BCErrInvalidRequest, bae.Code)
}

func TestValidateBCAuthorizeRequest_ScopeMissingOpenID(t *testing.T) {
	c := require.New(t)
	req := cibaSampleRequest()
	req.Scope = []string{"profile"}

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, cibaSampleClient()))
	c.True(ok)
	c.Equal(BCErrInvalidScope, bae.Code)
}

func TestValidateBCAuthorizeRequest_ScopeNotAllowedForClient(t *testing.T) {
	c := require.New(t)
	req := cibaSampleRequest()
	req.Scope = []string{"openid", "transfer"}

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, cibaSampleClient()))
	c.True(ok)
	c.Equal(BCErrInvalidScope, bae.Code)
}

func TestValidateBCAuthorizeRequest_MissingBindingMessage(t *testing.T) {
	c := require.New(t)
	req := cibaSampleRequest()
	req.BindingMessage = ""

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, cibaSampleClient()))
	c.True(ok)
	c.Equal(BCErrInvalidBindingMessage, bae.Code)
}

func TestValidateBCAuthorizeRequest_BindingMessageTooLong(t *testing.T) {
	c := require.New(t)
	req := cibaSampleRequest()
	req.BindingMessage = strings.Repeat("a", BindingMessageMaxLen+1)

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, cibaSampleClient()))
	c.True(ok)
	c.Equal(BCErrInvalidBindingMessage, bae.Code)
}

func TestValidateBCAuthorizeRequest_RejectsUnsupportedACR(t *testing.T) {
	c := require.New(t)
	req := cibaSampleRequest()
	req.ACRValues = []string{"urn:mfa-otp"}

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, cibaSampleClient()))
	c.True(ok)
	c.Equal(BCErrInvalidRequest, bae.Code)
}

func TestValidateBCAuthorizeRequest_PingRequiresClientNotificationToken(t *testing.T) {
	c := require.New(t)
	client := cibaSampleClient()
	mode := domain.CIBADeliveryPing
	client.BackchannelTokenDeliveryMode = &mode

	req := cibaSampleRequest()
	req.ClientNotificationToken = ""

	bae, ok := errors.AsType[*ErrBCAuthorize](ValidateBCAuthorizeRequest(req, client))
	c.True(ok)
	c.Equal(BCErrInvalidRequest, bae.Code)
}

func TestValidateBCAuthorizeRequest_PollDoesNotRequireToken(t *testing.T) {
	c := require.New(t)
	client := cibaSampleClient()
	mode := domain.CIBADeliveryPoll
	client.BackchannelTokenDeliveryMode = &mode

	req := cibaSampleRequest()
	req.ClientNotificationToken = ""

	c.NoError(ValidateBCAuthorizeRequest(req, client))
}

func TestClampRequestedExpiry(t *testing.T) {
	c := require.New(t)
	defaultTTL := 10 * time.Minute

	c.Equal(defaultTTL, ClampRequestedExpiry(0, defaultTTL), "zero falls through to default")
	c.Equal(defaultTTL, ClampRequestedExpiry(-1, defaultTTL), "negative falls through to default")
	c.Equal(time.Duration(RequestedExpiryMin)*time.Second, ClampRequestedExpiry(10, defaultTTL),
		"below the min is clamped up")
	c.Equal(time.Duration(RequestedExpiryMax)*time.Second, ClampRequestedExpiry(100000, defaultTTL),
		"above the max is clamped down")
	c.Equal(300*time.Second, ClampRequestedExpiry(300, defaultTTL),
		"value inside the window passes through")
}

func TestTruncateBindingMessage(t *testing.T) {
	c := require.New(t)
	short := "Authorize $50"
	c.Equal(short, TruncateBindingMessage(short))

	long := strings.Repeat("a", BindingMessageMaxLen+10)
	got := TruncateBindingMessage(long)
	c.LessOrEqual(len([]rune(got)), BindingMessageMaxLen)
	c.True(strings.HasSuffix(got, "…"))
}

func TestErrBCAuthorize_String(t *testing.T) {
	c := require.New(t)
	e := &ErrBCAuthorize{Code: BCErrInvalidScope, Description: "scope X not allowed"}
	c.Contains(e.Error(), "invalid_scope")
	c.Contains(e.Error(), "scope X not allowed")

	bare := &ErrBCAuthorize{Code: BCErrUnknownUserID}
	c.Contains(bare.Error(), "unknown_user_id")
}
