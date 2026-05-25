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
	clients      oidc.ClientLookup
	users        opUserByEmail
	cibaRequests cibaRequestIssuer
	approvalTks  approvalTokenIssuer
	notifier     notifier.AuthDeviceNotifier
	issuer       string
	defaultTTL   time.Duration
	pollInterval int
	logger       *slog.Logger
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
	// ApprovalTokens issues the URL-safe token embedded in the approval URL.
	ApprovalTokens approvalTokenIssuer
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
		clients:      deps.Clients,
		users:        deps.Users,
		cibaRequests: deps.CIBARequests,
		approvalTks:  deps.ApprovalTokens,
		notifier:     deps.Notifier,
		issuer:       deps.Issuer,
		defaultTTL:   deps.DefaultTTL,
		pollInterval: deps.PollInterval,
		logger:       deps.Logger,
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
