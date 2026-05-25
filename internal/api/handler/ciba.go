package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/notifier"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

// opUserByEmail captures the op_user store's GetByEmail path used to
// resolve a CIBA login_hint into an op_user_id.
type opUserByEmail interface {
	GetByEmail(ctx context.Context, email string) (*domain.OPUser, error)
}

// cibaRequestIssuer captures the Redis store path used to mint a fresh
// auth_req_id and persist the request payload with a TTL.
type cibaRequestIssuer interface {
	Issue(ctx context.Context, req domain.CIBARequest, ttl time.Duration) (string, error)
}

// approvalTokenIssuer captures the Redis store path used to mint the
// URL-safe single-use token that the notifier embeds in the approval URL.
type approvalTokenIssuer interface {
	Issue(ctx context.Context, authReqID string) (string, error)
}

// approvalTokenReader captures the read side of the approval-token store.
// Peek (not Consume) is used on the GET /ciba/approve page render so a
// reload does not invalidate the pending approval; the single-use
// guarantee lives at Consume on the POST.
type approvalTokenReader interface {
	Peek(ctx context.Context, token string) (string, error)
}

// cibaRequestReader captures the read side of the CIBARequest store
// used by GET /ciba/approve to render the binding message the user is
// being asked to authorize.
type cibaRequestReader interface {
	Get(ctx context.Context, authReqID string) (*domain.CIBARequest, error)
}

// CIBAHandler implements POST /oidc/bc-authorize. The flow:
//  1. authenticate the client
//  2. validate the request against the registered client
//  3. resolve login_hint into an op_user
//  4. issue a CIBARequest in Redis with the clamped TTL
//  5. issue a single-use approval_token bound to the auth_req_id
//  6. fire-and-await the notifier to deliver the approval URL
//  7. return { auth_req_id, expires_in, interval } to the RP
//
// If the notifier fails the request is rejected synchronously so the RP
// sees the problem immediately rather than after a long polling timeout.
type CIBAHandler struct {
	clients         oidc.ClientLookup
	users           opUserByEmail
	cibaRequests    cibaRequestIssuer
	cibaRequestsR   cibaRequestReader
	approvalTks     approvalTokenIssuer
	approvalTksR    approvalTokenReader
	notifier        notifier.AuthDeviceNotifier
	issuer          string
	defaultTTL      time.Duration
	pollInterval    int
	logger          *slog.Logger
}

// CIBAHandlerDeps bundles the collaborators CIBAHandler needs.
type CIBAHandlerDeps struct {
	// Clients resolves client_id → registered client and authenticates
	// the request via Basic / Post / none.
	Clients oidc.ClientLookup
	// Users resolves login_hint (email) into an op_user.
	Users opUserByEmail
	// CIBARequests issues new auth_req_id-keyed CIBARequest payloads.
	CIBARequests cibaRequestIssuer
	// CIBARequestsReader reads existing CIBARequests by auth_req_id, used
	// by the approval page to display the binding message.
	CIBARequestsReader cibaRequestReader
	// ApprovalTokens issues the URL-safe token embedded in the approval URL.
	ApprovalTokens approvalTokenIssuer
	// ApprovalTokensReader peeks the URL-safe token without consuming it,
	// used by the approval page render.
	ApprovalTokensReader approvalTokenReader
	// Notifier delivers the approval URL to the user's device.
	Notifier notifier.AuthDeviceNotifier
	// Issuer is the OP issuer URL — the approval URL is built off it.
	Issuer string
	// DefaultTTL is the CIBA request TTL used when the RP does not send
	// requested_expiry (or sends a value outside the allowed window).
	DefaultTTL time.Duration
	// PollInterval is the seconds value the OP returns in the response
	// so polling clients know how often to hit the token endpoint.
	PollInterval int
	// Logger receives one structured line per failure that warrants it.
	Logger *slog.Logger
}

// NewCIBAHandler returns a CIBAHandler from its dependencies.
func NewCIBAHandler(deps CIBAHandlerDeps) *CIBAHandler {
	return &CIBAHandler{
		clients:       deps.Clients,
		users:         deps.Users,
		cibaRequests:  deps.CIBARequests,
		cibaRequestsR: deps.CIBARequestsReader,
		approvalTks:   deps.ApprovalTokens,
		approvalTksR:  deps.ApprovalTokensReader,
		notifier:      deps.Notifier,
		issuer:        deps.Issuer,
		defaultTTL:    deps.DefaultTTL,
		pollInterval:  deps.PollInterval,
		logger:        deps.Logger,
	}
}

// Approve handles GET /ciba/approve?t=<approval_token>. The page itself
// is server-rendered HTML — there is no API surface other than the
// passkey ceremony endpoints the page calls when the user taps
// Authorize or Deny.
//
// Peek (not Consume) is used here so a page reload does not invalidate
// a pending approval; the single-use guarantee lives at POST
// /ciba/approve and POST /ciba/deny.
func (h *CIBAHandler) Approve(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	if token == "" {
		renderApprovalErrorPage(w, h.logger, http.StatusBadRequest,
			"This link is missing its token. Reopen the message you received.")
		return
	}

	authReqID, err := h.approvalTksR.Peek(r.Context(), token)
	if errors.Is(err, domain.ErrApprovalTokenNotFound) {
		renderApprovalErrorPage(w, h.logger, http.StatusNotFound,
			"This approval link has expired or already been used. Ask the app to send a new one.")
		return
	}
	if err != nil {
		h.logger.Error("approve: peek approval token", "err", err)
		renderApprovalErrorPage(w, h.logger, http.StatusInternalServerError, "Internal error.")
		return
	}

	req, err := h.cibaRequestsR.Get(r.Context(), authReqID)
	if errors.Is(err, domain.ErrCIBARequestNotFound) {
		renderApprovalErrorPage(w, h.logger, http.StatusNotFound,
			"The request behind this link has expired. Ask the app to start a new one.")
		return
	}
	if err != nil {
		h.logger.Error("approve: load ciba request", "err", err)
		renderApprovalErrorPage(w, h.logger, http.StatusInternalServerError, "Internal error.")
		return
	}

	switch req.Status {
	case domain.CIBAStatusApproved:
		renderApprovalTerminalPage(w, h.logger, "This request was already authorized.")
		return
	case domain.CIBAStatusDenied:
		renderApprovalTerminalPage(w, h.logger, "This request was already denied.")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, "approval.html", map[string]string{
		"ClientName":     req.ClientID,
		"BindingMessage": req.BindingMessage,
		"ApprovalToken":  token,
	}); err != nil {
		h.logger.Error("approve: render approval", "err", err)
	}
}

// renderApprovalErrorPage shows a minimal HTML page when the approval
// URL is broken (missing token, expired token, missing CIBA request).
func renderApprovalErrorPage(w http.ResponseWriter, logger *slog.Logger, status int, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Approval unavailable</title></head><body style="font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;color:#0f172a;"><h1 style="font-size:1.25rem;">Approval unavailable</h1><p>` +
		htmlEscape(description) + `</p></body></html>`

	if _, err := w.Write([]byte(body)); err != nil {
		logger.Error("approve: write error page", "err", err)
	}
}

// renderApprovalTerminalPage shows a minimal HTML page for already-
// approved or already-denied requests reached via the URL after the
// fact (e.g. user clicks the link from chat history).
func renderApprovalTerminalPage(w http.ResponseWriter, logger *slog.Logger, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	body := `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Already decided</title></head><body style="font-family:system-ui,sans-serif;max-width:480px;margin:4rem auto;padding:0 1rem;color:#0f172a;"><h1 style="font-size:1.25rem;">Already decided</h1><p>` +
		htmlEscape(description) + `</p></body></html>`

	if _, err := w.Write([]byte(body)); err != nil {
		logger.Error("approve: write terminal page", "err", err)
	}
}

// bcAuthorizeResponse is the success body for POST /oidc/bc-authorize.
type bcAuthorizeResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// BCAuthorize handles POST /oidc/bc-authorize.
func (h *CIBAHandler) BCAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}

	client, err := oidc.AuthenticateClient(r.Context(), r, h.clients)
	if err != nil {
		h.writeClientAuthError(w, err)
		return
	}

	req := oidc.BCAuthorizeRequest{
		ClientID:                client.ClientID,
		Scope:                   splitSpaceList(r.PostForm.Get("scope")),
		LoginHint:               strings.TrimSpace(r.PostForm.Get("login_hint")),
		BindingMessage:          r.PostForm.Get("binding_message"),
		ACRValues:               splitSpaceList(r.PostForm.Get("acr_values")),
		ClientNotificationToken: strings.TrimSpace(r.PostForm.Get("client_notification_token")),
		RequestedExpiry:         parseRequestedExpiry(r.PostForm.Get("requested_expiry")),
	}

	if vErr := oidc.ValidateBCAuthorizeRequest(req, client); vErr != nil {
		h.writeBCAuthorizeError(w, vErr)
		return
	}

	user, err := h.users.GetByEmail(r.Context(), strings.ToLower(req.LoginHint))
	if errors.Is(err, domain.ErrOPUserNotFound) {
		writeError(w, h.logger, http.StatusBadRequest, string(oidc.BCErrUnknownUserID),
			"login_hint does not resolve to a known user")
		return
	}
	if err != nil {
		h.logger.Error("bc-authorize: lookup op_user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	ttl := oidc.ClampRequestedExpiry(req.RequestedExpiry, h.defaultTTL)

	authReqID, err := h.cibaRequests.Issue(r.Context(), domain.CIBARequest{
		ClientID:                client.ClientID,
		OPUserID:                user.ID,
		Scope:                   req.Scope,
		BindingMessage:          oidc.TruncateBindingMessage(req.BindingMessage),
		ACRValues:               req.ACRValues,
		ClientNotificationToken: req.ClientNotificationToken,
	}, ttl)
	if err != nil {
		h.logger.Error("bc-authorize: issue ciba request", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	approvalToken, err := h.approvalTks.Issue(r.Context(), authReqID)
	if err != nil {
		h.logger.Error("bc-authorize: issue approval token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	approvalURL := buildApprovalURL(h.issuer, approvalToken)

	if err := h.notifier.Notify(r.Context(), notifier.Notification{
		User:           user,
		ClientName:     client.ClientID,
		BindingMessage: req.BindingMessage,
		ApprovalURL:    approvalURL,
	}); err != nil {
		// Fail loudly: if the user can't see the URL, the RP will sit
		// in authorization_pending until expired_token — bad UX.
		// Surfacing now lets the RP decide whether to retry or fall
		// back to a different channel.
		h.logger.Error("bc-authorize: notifier", "err", err, "auth_req_id", authReqID)
		writeError(w, h.logger, http.StatusServiceUnavailable, "notifier_unavailable",
			"could not deliver the approval link")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, bcAuthorizeResponse{
		AuthReqID: authReqID,
		ExpiresIn: int(ttl.Seconds()),
		Interval:  h.pollInterval,
	})
}

func (h *CIBAHandler) writeBCAuthorizeError(w http.ResponseWriter, err error) {
	bae, ok := errors.AsType[*oidc.ErrBCAuthorize](err)
	if !ok {
		h.logger.Error("bc-authorize: validate", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeError(w, h.logger, http.StatusBadRequest, string(bae.Code), bae.Description)
}

func (h *CIBAHandler) writeClientAuthError(w http.ResponseWriter, err error) {
	cae, ok := errors.AsType[*oidc.ErrClientAuth](err)
	if !ok {
		h.logger.Error("bc-authorize: client auth", "err", err)
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

// buildApprovalURL composes the URL the notifier delivers. The token is
// the only secret on the wire; auth_req_id is never exposed to the user
// so a screenshotted message cannot be re-targeted to a different
// request.
func buildApprovalURL(issuer, token string) string {
	base := strings.TrimRight(issuer, "/")
	return base + "/ciba/approve?t=" + token
}

// parseRequestedExpiry parses the requested_expiry form value. Missing
// or malformed input yields 0 — ClampRequestedExpiry then falls through
// to the OP-side default.
func parseRequestedExpiry(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}
