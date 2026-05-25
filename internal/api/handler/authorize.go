package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
)

// clientLookup captures only the bits of the Postgres client store the
// authorize handler needs. Defined here so tests can inject an in-memory
// fake without spinning up a real database.
type clientLookup interface {
	GetByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// opUserLookup captures the read-side of the op_user store the
// authorize-complete path uses to map a passkey_user_id back to an
// op_user row.
type opUserLookup interface {
	GetByPasskeyUserID(ctx context.Context, passkeyUserID uuid.UUID) (*domain.OPUser, error)
}

// authSessionStore captures the in-flight /authorize session store: a
// fresh id is issued at GET /authorize, consumed once at completion.
type authSessionStore interface {
	Issue(ctx context.Context, session domain.AuthSession) (string, error)
	Consume(ctx context.Context, id string) (domain.AuthSession, error)
}

// authCodeIssuer captures the single-use authorization-code store. Codes
// are minted only after the passkey assertion is verified.
type authCodeIssuer interface {
	Issue(ctx context.Context, code domain.AuthCode) (string, error)
}

// passkeyLoginClient captures the passkey-login half of the passkey
// service API used by the authorize flow.
type passkeyLoginClient interface {
	BeginLogin(ctx context.Context) (passkey.BeginLoginResponse, error)
	CompleteLogin(ctx context.Context, req passkey.CompleteLoginRequest) (passkey.CompleteLoginResponse, error)
}

// AuthorizeHandler implements GET /oidc/authorize plus the two POST
// endpoints the rendered login page calls to drive the passkey ceremony.
type AuthorizeHandler struct {
	clients      clientLookup
	users        opUserLookup
	sessions     authSessionStore
	authCodes    authCodeIssuer
	passkey      passkeyLoginClient
	logger       *slog.Logger
}

// NewAuthorizeHandler returns an AuthorizeHandler bound to its dependencies.
func NewAuthorizeHandler(
	clients clientLookup,
	users opUserLookup,
	sessions authSessionStore,
	authCodes authCodeIssuer,
	p passkeyLoginClient,
	logger *slog.Logger,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		clients:   clients,
		users:     users,
		sessions:  sessions,
		authCodes: authCodes,
		passkey:   p,
		logger:    logger,
	}
}

// Authorize handles GET /oidc/authorize. It parses query parameters,
// resolves the client, validates the request, persists an auth_session,
// and renders the login page. Validation failures either redirect to the
// RP (with ?error=...&state=...) when the redirect_uri is known to be
// safe, or render an HTML error page when it is not.
func (h *AuthorizeHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := oidc.AuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               splitSpaceList(q.Get("scope")),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
		ACRValues:           splitSpaceList(q.Get("acr_values")),
		LoginHint:           q.Get("login_hint"),
	}

	if req.ClientID == "" {
		renderAuthorizeErrorPage(w, h.logger, http.StatusBadRequest,
			"client_id is required")
		return
	}

	client, err := h.clients.GetByClientID(r.Context(), req.ClientID)
	if errors.Is(err, domain.ErrClientNotFound) {
		renderAuthorizeErrorPage(w, h.logger, http.StatusBadRequest,
			"client_id is not registered")
		return
	}
	if err != nil {
		h.logger.Error("authorize: client lookup", "err", err)
		renderAuthorizeErrorPage(w, h.logger, http.StatusInternalServerError,
			"internal error")
		return
	}

	if vErr := oidc.ValidateAuthorizeRequest(req, client); vErr != nil {
		ae := oidc.AsAuthorizeError(vErr)
		if ae != nil && ae.SafeRedirect {
			http.Redirect(w, r, buildErrorRedirect(req.RedirectURI, ae, req.State), http.StatusFound)
			return
		}
		desc := "invalid request"
		if ae != nil {
			desc = ae.Description
		}
		renderAuthorizeErrorPage(w, h.logger, http.StatusBadRequest, desc)
		return
	}

	sessionID, err := h.sessions.Issue(r.Context(), domain.AuthSession{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		ACRValues:           req.ACRValues,
		LoginHint:           req.LoginHint,
	})
	if err != nil {
		h.logger.Error("authorize: issue session", "err", err)
		renderAuthorizeErrorPage(w, h.logger, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, "login.html", map[string]string{
		"ClientID":      req.ClientID,
		"AuthSessionID": sessionID,
	}); err != nil {
		h.logger.Error("authorize: render login", "err", err)
	}
}

// loginBeginResponse is the JSON shape the login page receives from
// POST /oidc/authorize/login/begin.
type loginBeginResponse struct {
	Options   json.RawMessage `json:"options"`
	SessionID string          `json:"session_id"`
}

// LoginBegin handles POST /oidc/authorize/login/begin. It proxies a
// discoverable-login ceremony to the passkey service and returns the
// options and session id to the browser. The auth_session_id is not
// touched here — it lives until the corresponding /complete call.
func (h *AuthorizeHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	begin, err := h.passkey.BeginLogin(r.Context())
	if err != nil {
		h.mapPasskeyError(w, "authorize login begin", err)
		return
	}

	writeJSON(w, h.logger, http.StatusOK, loginBeginResponse{
		Options:   begin.Options,
		SessionID: begin.SessionID,
	})
}

// loginCompleteRequest is the body of POST /oidc/authorize/login/complete.
type loginCompleteRequest struct {
	AuthSessionID    string          `json:"auth_session_id"`
	PasskeySessionID string          `json:"passkey_session_id"`
	Credential       json.RawMessage `json:"credential"`
}

// loginCompleteResponse is the body of a successful login complete: the
// fully built RP redirect URL carrying ?code=...&state=...
type loginCompleteResponse struct {
	RedirectURL string `json:"redirect_url"`
}

// LoginComplete handles POST /oidc/authorize/login/complete. It consumes
// the auth_session, brokers CompleteLogin to the passkey service,
// resolves the passkey-side user to an op_user, mints an authorization
// code, and returns the final redirect URL for the browser to navigate.
func (h *AuthorizeHandler) LoginComplete(w http.ResponseWriter, r *http.Request) {
	var req loginCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}

	if req.AuthSessionID == "" || req.PasskeySessionID == "" || len(req.Credential) == 0 {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"auth_session_id, passkey_session_id, and credential are required")
		return
	}

	session, err := h.sessions.Consume(r.Context(), req.AuthSessionID)
	if errors.Is(err, domain.ErrAuthSessionNotFound) {
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid",
			"authorization session expired or already consumed")
		return
	}
	if err != nil {
		h.logger.Error("authorize complete: consume session", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	complete, err := h.passkey.CompleteLogin(r.Context(), passkey.CompleteLoginRequest{
		SessionID:  req.PasskeySessionID,
		Credential: req.Credential,
	})
	if err != nil {
		h.mapPasskeyError(w, "authorize login complete", err)
		return
	}

	passkeyUserID, err := uuid.Parse(complete.UserID)
	if err != nil {
		h.logger.Error("authorize complete: parse user_id", "err", err, "raw", complete.UserID)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable",
			"passkey service returned an invalid user_id")
		return
	}

	user, err := h.users.GetByPasskeyUserID(r.Context(), passkeyUserID)
	if errors.Is(err, domain.ErrOPUserNotFound) {
		writeError(w, h.logger, http.StatusForbidden, "user_unknown",
			"this passkey is not linked to an account on this provider")
		return
	}
	if err != nil {
		h.logger.Error("authorize complete: lookup op_user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	code, err := h.authCodes.Issue(r.Context(), domain.AuthCode{
		ClientID:            session.ClientID,
		OPUserID:            user.ID,
		RedirectURI:         session.RedirectURI,
		Scope:               session.Scope,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
		Nonce:               session.Nonce,
		ACR:                 "urn:passkey",
		AMR:                 []string{"webauthn", "user"},
		IssuedAt:            nowUTC(),
	})
	if err != nil {
		h.logger.Error("authorize complete: issue code", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, loginCompleteResponse{
		RedirectURL: buildCodeRedirect(session.RedirectURI, code, session.State),
	})
}

func (h *AuthorizeHandler) mapPasskeyError(w http.ResponseWriter, op string, err error) {
	var serr *passkey.ServiceError
	switch {
	case errors.As(err, &serr):
		switch serr.Code {
		case "session_invalid":
			writeError(w, h.logger, http.StatusUnauthorized, "session_invalid", "passkey session expired")
		case "credential_not_found", "no_credential":
			writeError(w, h.logger, http.StatusForbidden, "user_unknown",
				"this passkey is not registered with the passkey service")
		case "invalid_request", "attestation_rejected":
			writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "passkey ceremony failed")
		default:
			h.logger.Warn("passkey "+op, "status", serr.Status, "code", serr.Code)
			writeError(w, h.logger, http.StatusBadGateway, "service_unavailable",
				"passkey service returned an error")
		}
	case errors.Is(err, passkey.ErrServiceUnavailable),
		errors.Is(err, passkey.ErrTransport):
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable",
			"could not reach passkey service")
	default:
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
	}
}

// splitSpaceList parses a space-separated form value (scope, acr_values)
// into a deduplicated string slice. Empty input returns nil.
func splitSpaceList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return nil
	}
	return parts
}

// buildCodeRedirect builds the RP redirect URL for a successful auth-code
// issuance: redirect_uri + ?code=...&state=...
func buildCodeRedirect(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// redirectURI was validated against the client's registered list
		// before reaching this point; failure here would only happen if a
		// caller bypassed validation. Surface a sentinel rather than
		// returning an unparseable string downstream.
		return ""
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// buildErrorRedirect builds the RP redirect URL for a safe-redirect error:
// redirect_uri + ?error=...&error_description=...&state=...
func buildErrorRedirect(redirectURI string, ae *oidc.AuthorizeError, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}

	q := u.Query()
	q.Set("error", string(ae.Code))
	if ae.Description != "" {
		q.Set("error_description", ae.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// renderAuthorizeErrorPage renders a minimal HTML error page for cases
// where redirecting to the RP would create an open redirector (unknown
// client_id, unregistered redirect_uri).
func renderAuthorizeErrorPage(w http.ResponseWriter, logger *slog.Logger, status int, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	body := fmt.Sprintf(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Authorization error</title></head><body style="font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;color:#0f172a;"><h1 style="font-size:1.25rem;">Authorization error</h1><p>%s</p></body></html>`,
		htmlEscape(description),
	)

	if _, err := w.Write([]byte(body)); err != nil {
		logger.Error("authorize: write error page", "err", err)
	}
}

// htmlEscape is a minimal escape for the error description shown to the
// user. The descriptions come from sentinel cases (no untrusted input),
// but we escape defensively in case a future caller drifts.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", `'`, "&#39;")
	return r.Replace(s)
}
