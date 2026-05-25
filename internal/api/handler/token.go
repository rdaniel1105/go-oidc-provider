package handler

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

// authCodeConsumer captures the single-use authorization-code store
// consumption path.
type authCodeConsumer interface {
	Consume(ctx context.Context, code string) (*domain.AuthCode, error)
}

// refreshTokenCreator captures the persistence side of the refresh-token
// store. Rotation (lookup + revoke + family-wide takedown) lands alongside
// the refresh-token grant in a later phase.
type refreshTokenCreator interface {
	Create(ctx context.Context, t *domain.RefreshToken) (*domain.RefreshToken, error)
}

// opUserByID captures the op_user store's GetByID path used to fetch the
// subject we're minting tokens for.
type opUserByID interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.OPUser, error)
}

// activeKeySource exposes the active signing key + kid. *oidc.KeyStore
// satisfies this directly.
type activeKeySource interface {
	Active() (kid string, priv *ecdsa.PrivateKey, err error)
}

// TokenHandler implements POST /oidc/token. v1 covers only the
// authorization_code grant; refresh_token rotation and the CIBA grant
// land in later phases.
type TokenHandler struct {
	clients    oidc.ClientLookup
	authCodes  authCodeConsumer
	users      opUserByID
	refresh    refreshTokenCreator
	keys       activeKeySource
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
	logger     *slog.Logger
}

// TokenHandlerDeps bundles the collaborators TokenHandler needs.
type TokenHandlerDeps struct {
	// Clients resolves client_id → registered client. Used for both
	// authentication and binding-check of the consumed auth_code.
	Clients oidc.ClientLookup
	// AuthCodes consumes single-use authorization codes.
	AuthCodes authCodeConsumer
	// Users fetches the subject op_user by id.
	Users opUserByID
	// Refresh persists newly issued refresh-token rows.
	Refresh refreshTokenCreator
	// Keys provides the active ES256 signing key + kid for token signing.
	Keys activeKeySource
	// Issuer is the OP issuer URL, copied verbatim into iss / aud claims.
	Issuer string
	// AccessTTL bounds the lifetime of access + ID tokens.
	AccessTTL time.Duration
	// RefreshTTL bounds the lifetime of issued refresh tokens.
	RefreshTTL time.Duration
	// Logger receives one structured line per failure path that warrants it.
	Logger *slog.Logger
}

// NewTokenHandler returns a TokenHandler from its dependencies.
func NewTokenHandler(deps TokenHandlerDeps) *TokenHandler {
	return &TokenHandler{
		clients:    deps.Clients,
		authCodes:  deps.AuthCodes,
		users:      deps.Users,
		refresh:    deps.Refresh,
		keys:       deps.Keys,
		issuer:     deps.Issuer,
		accessTTL:  deps.AccessTTL,
		refreshTTL: deps.RefreshTTL,
		logger:     deps.Logger,
	}
}

// tokenResponse is the OAuth/OIDC token endpoint success response shape.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles POST /oidc/token. The handler is grant-aware: only
// authorization_code is supported in v1; other grants return
// unsupported_grant_type.
func (h *TokenHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}

	client, err := oidc.AuthenticateClient(r.Context(), r, h.clients)
	if err != nil {
		h.writeClientAuthError(w, err)
		return
	}

	grant := r.PostForm.Get("grant_type")
	switch grant {
	case "authorization_code":
		h.handleAuthorizationCode(w, r, client)
	default:
		writeError(w, h.logger, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type "+grant+" is not supported at this endpoint")
	}
}

func (h *TokenHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request, client *domain.Client) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")

	if code == "" || redirectURI == "" || verifier == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"code, redirect_uri, and code_verifier are required")
		return
	}

	authCode, err := h.authCodes.Consume(r.Context(), code)
	if errors.Is(err, domain.ErrAuthCodeNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"authorization code is unknown or already used")
		return
	}
	if err != nil {
		h.logger.Error("token: consume auth code", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if authCode.ClientID != client.ClientID {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"authorization code was issued to a different client")
		return
	}

	if authCode.RedirectURI != redirectURI {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"redirect_uri does not match the value submitted at /authorize")
		return
	}

	if !oidc.VerifyPKCE(verifier, authCode.CodeChallenge) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"code_verifier does not match the committed code_challenge")
		return
	}

	user, err := h.users.GetByID(r.Context(), authCode.OPUserID)
	if errors.Is(err, domain.ErrOPUserNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"the user backing this code no longer exists")
		return
	}
	if err != nil {
		h.logger.Error("token: lookup op_user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	kid, priv, err := h.keys.Active()
	if err != nil {
		h.logger.Error("token: active key", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	now := nowUTC()
	accessExpiry := now.Add(h.accessTTL)

	accessToken, err := oidc.MintAccessToken(oidc.AccessTokenInput{
		Issuer:    h.issuer,
		SubjectID: user.ID.String(),
		ClientID:  client.ClientID,
		IssuedAt:  now,
		Expiry:    accessExpiry,
		Scope:     authCode.Scope,
	}, priv, kid)
	if err != nil {
		h.logger.Error("token: mint access token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	phone := ""
	if user.PhoneE164 != nil {
		phone = *user.PhoneE164
	}
	_ = phone // phone is not currently emitted as a claim; reserved for a later scope

	idToken, err := oidc.MintIDToken(oidc.IDTokenInput{
		Issuer:    h.issuer,
		SubjectID: user.ID.String(),
		Audience:  client.ClientID,
		IssuedAt:  now,
		Expiry:    accessExpiry,
		AuthTime:  authCode.IssuedAt,
		Nonce:     authCode.Nonce,
		ACR:       authCode.ACR,
		AMR:       authCode.AMR,
		Scope:     authCode.Scope,
		Email:     user.Email,
		Name:      user.DisplayName,
	}, priv, kid)
	if err != nil {
		h.logger.Error("token: mint id token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	refreshRaw, refreshHash, err := oidc.NewRefreshToken()
	if err != nil {
		h.logger.Error("token: new refresh token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if _, err := h.refresh.Create(r.Context(), &domain.RefreshToken{
		TokenHash: refreshHash,
		ClientID:  client.ClientID,
		OPUserID:  user.ID,
		Scope:     authCode.Scope,
		ExpiresAt: now.Add(h.refreshTTL),
	}); err != nil {
		h.logger.Error("token: persist refresh token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.accessTTL.Seconds()),
		Scope:        strings.Join(authCode.Scope, " "),
	})
}

func (h *TokenHandler) writeClientAuthError(w http.ResponseWriter, err error) {
	cae := oidc.AsClientAuthError(err)
	if cae == nil {
		h.logger.Error("token: client auth", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if cae.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", cae.WWWAuthenticate)
	}

	status := http.StatusUnauthorized
	if cae.Code == oidc.ClientAuthErrInvalidRequest {
		status = http.StatusBadRequest
	}

	writeError(w, h.logger, status, string(cae.Code), cae.Description)
}
