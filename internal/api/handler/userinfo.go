package handler

import (
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

// UserInfoHandler implements GET /oidc/userinfo. The endpoint is
// Bearer-protected: callers present an access token signed by this OP,
// and the handler emits the subset of identity claims the token's scope
// authorized.
type UserInfoHandler struct {
	keys   oidc.PublicKeyResolver
	users  opUserByID
	issuer string
	logger *slog.Logger
}

// NewUserInfoHandler returns a UserInfoHandler bound to the given key
// resolver and op_user store.
func NewUserInfoHandler(keys oidc.PublicKeyResolver, users opUserByID, issuer string, logger *slog.Logger) *UserInfoHandler {
	return &UserInfoHandler{keys: keys, users: users, issuer: issuer, logger: logger}
}

// userInfoResponse is the JSON shape emitted by /oidc/userinfo. Only
// fields the granted scope authorizes are populated; sub is always
// present.
type userInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	PhoneNumber   string `json:"phone_number,omitempty"`
}

// UserInfo handles GET /oidc/userinfo. Returns 401 with the standard
// WWW-Authenticate header on any token failure; on success returns the
// claims the access token's scope authorized.
func (h *UserInfoHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	token, ok := extractBearerToken(r)
	if !ok {
		h.writeUnauthorized(w, "Bearer", "missing or malformed Authorization header")
		return
	}

	claims, err := oidc.VerifyAccessToken(token, h.keys, h.issuer, time.Now())
	if err != nil {
		desc := "invalid token"
		if errors.Is(err, oidc.ErrAccessTokenExpired) {
			desc = "token expired"
		}
		h.writeUnauthorized(w, "Bearer", desc)
		return
	}

	subjectID, err := uuid.Parse(claims.Subject)
	if err != nil {
		h.logger.Warn("userinfo: subject is not a uuid", "sub", claims.Subject)
		h.writeUnauthorized(w, "Bearer", "invalid token subject")
		return
	}

	user, err := h.users.GetByID(r.Context(), subjectID)
	if errors.Is(err, domain.ErrOPUserNotFound) {
		h.writeUnauthorized(w, "Bearer", "token subject no longer exists")
		return
	}
	if err != nil {
		h.logger.Error("userinfo: lookup op_user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	scopes := oidc.ScopeList(claims.Scope)
	out := userInfoResponse{Sub: user.ID.String()}

	if slices.Contains(scopes, "email") && user.Email != "" {
		out.Email = user.Email
		verified := true
		out.EmailVerified = &verified
	}
	if slices.Contains(scopes, "profile") {
		out.Name = user.DisplayName
	}
	if slices.Contains(scopes, "phone") && user.PhoneE164 != nil {
		out.PhoneNumber = *user.PhoneE164
	}

	writeJSON(w, h.logger, http.StatusOK, out)
}

// writeUnauthorized writes the standard Bearer-protected 401 response.
// The error code is fixed to invalid_token per RFC 6750 §3.
func (h *UserInfoHandler) writeUnauthorized(w http.ResponseWriter, scheme, description string) {
	w.Header().Set("WWW-Authenticate", scheme+` error="invalid_token", error_description="`+description+`"`)
	writeError(w, h.logger, http.StatusUnauthorized, "invalid_token", description)
}

// extractBearerToken pulls the token off Authorization: Bearer <token>.
// The check is case-sensitive on the scheme name per RFC 6750 §2.1.
func extractBearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

