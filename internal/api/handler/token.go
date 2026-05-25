package handler

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net/http"
	"slices"
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

// cibaRequestRedeemer captures the read + delete pair used by the token
// endpoint's CIBA-grant branch to consume an auth_req_id after a
// successful approved redemption so the same id cannot mint two pairs.
type cibaRequestRedeemer interface {
	Get(ctx context.Context, authReqID string) (*domain.CIBARequest, error)
	Delete(ctx context.Context, authReqID string) error
}

// refreshTokenStore captures the full lifecycle the token endpoint needs:
// issuance at auth-code grant, lookup-by-hash + revocation at rotation,
// and family-wide takedown when a stolen token is replayed.
type refreshTokenStore interface {
	Create(ctx context.Context, t *domain.RefreshToken) (*domain.RefreshToken, error)
	GetByHash(ctx context.Context, hash string) (*domain.RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID, at time.Time) error
	RevokeFamily(ctx context.Context, familyID uuid.UUID, at time.Time) (int64, error)
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

// TokenHandler implements POST /oidc/token across the authorization_code,
// refresh_token, and CIBA grants.
type TokenHandler struct {
	clients      oidc.ClientLookup
	authCodes    authCodeConsumer
	users        opUserByID
	refresh      refreshTokenStore
	ciba         cibaRequestRedeemer
	keys         activeKeySource
	issuer       string
	accessTTL    time.Duration
	refreshTTL   time.Duration
	pollInterval int
	logger       *slog.Logger
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
	Refresh refreshTokenStore
	// CIBA reads + deletes auth_req_id-keyed CIBARequests for the CIBA
	// grant's polling exchange.
	CIBA cibaRequestRedeemer
	// Keys provides the active ES256 signing key + kid for token signing.
	Keys activeKeySource
	// Issuer is the OP issuer URL, copied verbatim into iss / aud claims.
	Issuer string
	// AccessTTL bounds the lifetime of access + ID tokens.
	AccessTTL time.Duration
	// RefreshTTL bounds the lifetime of issued refresh tokens.
	RefreshTTL time.Duration
	// PollInterval is the seconds value the OP advertised at /bc-authorize.
	// Currently used only for slow-down decisions; v1 does not implement
	// slow_down, but holding it here keeps the wiring honest.
	PollInterval int
	// Logger receives one structured line per failure path that warrants it.
	Logger *slog.Logger
}

// NewTokenHandler returns a TokenHandler from its dependencies.
func NewTokenHandler(deps TokenHandlerDeps) *TokenHandler {
	return &TokenHandler{
		clients:      deps.Clients,
		authCodes:    deps.AuthCodes,
		users:        deps.Users,
		refresh:      deps.Refresh,
		ciba:         deps.CIBA,
		keys:         deps.Keys,
		issuer:       deps.Issuer,
		accessTTL:    deps.AccessTTL,
		refreshTTL:   deps.RefreshTTL,
		pollInterval: deps.PollInterval,
		logger:       deps.Logger,
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
	case "refresh_token":
		h.handleRefreshToken(w, r, client)
	case oidc.CIBAGrantType:
		h.handleCIBA(w, r, client)
	default:
		writeError(w, h.logger, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type "+grant+" is not supported at this endpoint")
	}
}

// handleCIBA implements the polling redemption of a CIBA auth_req_id at
// the token endpoint. Branches on the underlying request's lifecycle:
//
//   - not found → expired_token (TTL ran out or already redeemed)
//   - wrong client → invalid_grant
//   - pending → authorization_pending (RP polls again after `interval`)
//   - denied → access_denied
//   - approved → mint tokens, delete the request (single-use redemption)
//
// slow_down is intentionally not implemented in v1; clients honoring the
// advertised interval will not be told to slow down regardless of how
// fast they actually poll, which is fine for a single-tenant demo OP.
func (h *TokenHandler) handleCIBA(w http.ResponseWriter, r *http.Request, client *domain.Client) {
	authReqID := strings.TrimSpace(r.PostForm.Get("auth_req_id"))
	if authReqID == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"auth_req_id is required")
		return
	}

	cibaReq, err := h.ciba.Get(r.Context(), authReqID)
	if errors.Is(err, domain.ErrCIBARequestNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, "expired_token",
			"auth_req_id is unknown or expired")
		return
	}
	if err != nil {
		h.logger.Error("token: lookup ciba request", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if cibaReq.ClientID != client.ClientID {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"auth_req_id was issued to a different client")
		return
	}

	switch cibaReq.Status {
	case domain.CIBAStatusPending:
		writeError(w, h.logger, http.StatusBadRequest, "authorization_pending",
			"the user has not yet approved or denied the request")
		return
	case domain.CIBAStatusDenied:
		// Burn the request so a denied auth_req_id cannot be replayed
		// for repeated access_denied polls — keeps Redis tidy.
		if err := h.ciba.Delete(r.Context(), authReqID); err != nil {
			h.logger.Error("token: delete denied ciba request", "err", err)
		}
		writeError(w, h.logger, http.StatusBadRequest, "access_denied",
			"the user declined the request")
		return
	case domain.CIBAStatusApproved:
		// Fall through to token minting.
	default:
		h.logger.Error("token: unknown ciba status", "status", cibaReq.Status)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	user, err := h.users.GetByID(r.Context(), cibaReq.OPUserID)
	if errors.Is(err, domain.ErrOPUserNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"the user backing this request no longer exists")
		return
	}
	if err != nil {
		h.logger.Error("token: lookup op_user for ciba", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	// auth_time on a CIBA-issued ID token is the moment the user pressed
	// Authorize — captured on the request when the approval ceremony
	// completed. Fall back to IssuedAt for the corner case where the
	// store didn't stamp it (defensive — the transitioner always does).
	authTime := cibaReq.IssuedAt
	if cibaReq.ApprovedAt != nil {
		authTime = *cibaReq.ApprovedAt
	}

	tokens, err := mintCIBATokens(r.Context(), mintCIBATokensInput{
		Client:     client,
		User:       user,
		Scope:      cibaReq.Scope,
		AuthTime:   authTime,
		Issuer:     h.issuer,
		AccessTTL:  h.accessTTL,
		RefreshTTL: h.refreshTTL,
	}, h.keys)
	if err != nil {
		h.logger.Error("token: mint ciba token set", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if err := persistCIBARefreshRow(r.Context(), h.refresh, client, user, cibaReq.Scope, tokens.RefreshHash, authTime, tokens.RefreshExp); err != nil {
		h.logger.Error("token: persist refresh token (ciba)", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	// Successful single-use redemption — delete the CIBARequest so a
	// follow-up poll gets expired_token rather than another token pair.
	// Tokens are already in the response on the wire; a Delete failure
	// here is logged but does not undo the response (and the request
	// will TTL-expire shortly regardless).
	if err := h.ciba.Delete(r.Context(), authReqID); err != nil {
		h.logger.Error("token: delete redeemed ciba request", "err", err, "auth_req_id", authReqID)
	}

	writeJSON(w, h.logger, http.StatusOK, tokenResponse{
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.accessTTL.Seconds()),
		Scope:        strings.Join(cibaReq.Scope, " "),
	})
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
		FamilyID:  uuid.New(),
		Scope:     authCode.Scope,
		AuthTime:  authCode.IssuedAt,
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

func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request, client *domain.Client) {
	raw := r.PostForm.Get("refresh_token")
	if raw == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"refresh_token is required")
		return
	}

	presented, err := h.refresh.GetByHash(r.Context(), oidc.HashRefreshToken(raw))
	if errors.Is(err, domain.ErrRefreshTokenNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"refresh_token is unknown")
		return
	}
	if err != nil {
		h.logger.Error("token: lookup refresh token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if presented.ClientID != client.ClientID {
		// Mismatched client — treat as theft signal and burn the family.
		// The legitimate holder will have to re-authenticate.
		if _, revErr := h.refresh.RevokeFamily(r.Context(), presented.FamilyID, nowUTC()); revErr != nil {
			h.logger.Error("token: revoke family on client mismatch", "err", revErr)
		}
		h.logger.Warn("token: refresh client mismatch", "presented_client", client.ClientID, "row_client", presented.ClientID)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"refresh_token was issued to a different client")
		return
	}

	if presented.IsRevoked() {
		// Replay of an already-revoked token. The legitimate user holds
		// some descendant of this family by now; revoke the whole chain
		// to force a fresh authentication.
		if _, revErr := h.refresh.RevokeFamily(r.Context(), presented.FamilyID, nowUTC()); revErr != nil {
			h.logger.Error("token: revoke family on replay", "err", revErr)
		}
		h.logger.Warn("token: refresh replay detected", "family_id", presented.FamilyID)
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"refresh_token has been revoked")
		return
	}

	now := nowUTC()
	if presented.IsExpired(now) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"refresh_token is expired")
		return
	}

	scope, err := narrowRefreshScope(presented.Scope, r.PostForm.Get("scope"))
	if err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}

	if err := h.refresh.Revoke(r.Context(), presented.ID, now); err != nil {
		h.logger.Error("token: revoke rotated refresh", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	user, err := h.users.GetByID(r.Context(), presented.OPUserID)
	if errors.Is(err, domain.ErrOPUserNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_grant",
			"the user backing this refresh_token no longer exists")
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

	accessExpiry := now.Add(h.accessTTL)

	accessToken, err := oidc.MintAccessToken(oidc.AccessTokenInput{
		Issuer:    h.issuer,
		SubjectID: user.ID.String(),
		ClientID:  client.ClientID,
		IssuedAt:  now,
		Expiry:    accessExpiry,
		Scope:     scope,
	}, priv, kid)
	if err != nil {
		h.logger.Error("token: mint access token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	// ID token at refresh: omit nonce (the original nonce only binds the
	// initial auth-code response). auth_time carries through from the
	// row so the RP still sees when the user really authenticated, not
	// when they last refreshed.
	idToken, err := oidc.MintIDToken(oidc.IDTokenInput{
		Issuer:    h.issuer,
		SubjectID: user.ID.String(),
		Audience:  client.ClientID,
		IssuedAt:  now,
		Expiry:    accessExpiry,
		AuthTime:  presented.AuthTime,
		ACR:       "urn:passkey",
		AMR:       []string{"webauthn", "user"},
		Scope:     scope,
		Email:     user.Email,
		Name:      user.DisplayName,
	}, priv, kid)
	if err != nil {
		h.logger.Error("token: mint id token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	newRaw, newHash, err := oidc.NewRefreshToken()
	if err != nil {
		h.logger.Error("token: new refresh token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if _, err := h.refresh.Create(r.Context(), &domain.RefreshToken{
		TokenHash: newHash,
		ClientID:  client.ClientID,
		OPUserID:  user.ID,
		FamilyID:  presented.FamilyID,
		Scope:     scope,
		AuthTime:  presented.AuthTime,
		ExpiresAt: now.Add(h.refreshTTL),
	}); err != nil {
		h.logger.Error("token: persist rotated refresh", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: newRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.accessTTL.Seconds()),
		Scope:        strings.Join(scope, " "),
	})
}

// narrowRefreshScope enforces that any RP-requested scope at the refresh
// endpoint is a (non-strict) subset of the scope already granted on the
// original code. Widening is rejected. Empty input means "keep the
// original scope".
func narrowRefreshScope(granted []string, requested string) ([]string, error) {
	parts := splitSpaceList(requested)
	if len(parts) == 0 {
		return granted, nil
	}

	for _, p := range parts {
		if !slices.Contains(granted, p) {
			return nil, errors.New("scope " + p + " was not part of the original grant")
		}
	}

	return parts, nil
}

func (h *TokenHandler) writeClientAuthError(w http.ResponseWriter, err error) {
	cae, ok := errors.AsType[*oidc.ErrClientAuth](err)
	if !ok {
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
