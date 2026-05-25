package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/notifier"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
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

// approvalTokenConsumer captures the single-use consume path. Action
// endpoints (POST /ciba/approve, POST /ciba/deny) consume the token so
// only one terminal action can land per pending request.
type approvalTokenConsumer interface {
	Consume(ctx context.Context, token string) (string, error)
}

// cibaRequestTransitioner captures the state-transition path of the
// CIBARequest store. The store enforces "Pending only" semantics, so
// the handler does not need its own check beyond mapping ErrCIBANotPending.
type cibaRequestTransitioner interface {
	Approve(ctx context.Context, authReqID string, at time.Time) error
	Deny(ctx context.Context, authReqID string, at time.Time) error
}

// opUserByPasskeyIDLookup captures the op_user store's GetByPasskeyUserID
// path used after a successful passkey assertion to map the passkey-side
// user back to an op_user.
type opUserByPasskeyIDLookup interface {
	GetByPasskeyUserID(ctx context.Context, passkeyUserID uuid.UUID) (*domain.OPUser, error)
}

// cibaCallbackClient captures the OP→RP callback used in ping (and
// later push) delivery modes. The handler calls it best-effort after a
// terminal transition; a failure here is logged but does not roll back
// the approval / denial.
type cibaCallbackClient interface {
	Ping(ctx context.Context, endpoint, clientNotificationToken, authReqID string) error
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
	usersByPasskey  opUserByPasskeyIDLookup
	cibaRequests    cibaRequestIssuer
	cibaRequestsR   cibaRequestReader
	cibaRequestsT   cibaRequestTransitioner
	approvalTks     approvalTokenIssuer
	approvalTksR    approvalTokenReader
	approvalTksC    approvalTokenConsumer
	passkey         passkeyLoginClient
	notifier        notifier.AuthDeviceNotifier
	callback        cibaCallbackClient
	issuer          string
	defaultTTL      time.Duration
	pollInterval    int
	callbackTimeout time.Duration
	logger          *slog.Logger
}

// CIBAHandlerDeps bundles the collaborators CIBAHandler needs.
type CIBAHandlerDeps struct {
	// Clients resolves client_id → registered client and authenticates
	// the request via Basic / Post / none.
	Clients oidc.ClientLookup
	// Users resolves login_hint (email) into an op_user.
	Users opUserByEmail
	// UsersByPasskey resolves the passkey-side user_id returned by the
	// passkey service into an op_user, used to enforce the login_hint
	// match at approval time.
	UsersByPasskey opUserByPasskeyIDLookup
	// CIBARequests issues new auth_req_id-keyed CIBARequest payloads.
	CIBARequests cibaRequestIssuer
	// CIBARequestsReader reads existing CIBARequests by auth_req_id, used
	// by the approval page to display the binding message.
	CIBARequestsReader cibaRequestReader
	// CIBARequestsTransitioner transitions a pending CIBARequest to its
	// terminal state (approved or denied).
	CIBARequestsTransitioner cibaRequestTransitioner
	// ApprovalTokens issues the URL-safe token embedded in the approval URL.
	ApprovalTokens approvalTokenIssuer
	// ApprovalTokensReader peeks the URL-safe token without consuming it,
	// used by the approval page render.
	ApprovalTokensReader approvalTokenReader
	// ApprovalTokensConsumer consumes the URL-safe token at terminal
	// actions (POST /ciba/approve, POST /ciba/deny) to enforce single-use.
	ApprovalTokensConsumer approvalTokenConsumer
	// Passkey is the HTTP client used to broker BeginLogin / CompleteLogin
	// against go-passkey-auth during the approval ceremony.
	Passkey passkeyLoginClient
	// Notifier delivers the approval URL to the user's device.
	Notifier notifier.AuthDeviceNotifier
	// Callback POSTs the RP's client_notification_endpoint after a
	// terminal CIBA transition for ping- and push-mode clients. May be
	// nil — in that case the OP behaves as if every client were
	// configured for poll delivery.
	Callback cibaCallbackClient
	// Issuer is the OP issuer URL — the approval URL is built off it.
	Issuer string
	// DefaultTTL is the CIBA request TTL used when the RP does not send
	// requested_expiry (or sends a value outside the allowed window).
	DefaultTTL time.Duration
	// PollInterval is the seconds value the OP returns in the response
	// so polling clients know how often to hit the token endpoint.
	PollInterval int
	// CallbackTimeout caps how long the OP waits on the RP's
	// notification endpoint. Defaults to 5 seconds when zero.
	CallbackTimeout time.Duration
	// Logger receives one structured line per failure that warrants it.
	Logger *slog.Logger
}

// NewCIBAHandler returns a CIBAHandler from its dependencies.
func NewCIBAHandler(deps CIBAHandlerDeps) *CIBAHandler {
	timeout := deps.CallbackTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &CIBAHandler{
		clients:         deps.Clients,
		users:           deps.Users,
		usersByPasskey:  deps.UsersByPasskey,
		cibaRequests:    deps.CIBARequests,
		cibaRequestsR:   deps.CIBARequestsReader,
		cibaRequestsT:   deps.CIBARequestsTransitioner,
		approvalTks:     deps.ApprovalTokens,
		approvalTksR:    deps.ApprovalTokensReader,
		approvalTksC:    deps.ApprovalTokensConsumer,
		passkey:         deps.Passkey,
		notifier:        deps.Notifier,
		callback:        deps.Callback,
		issuer:          deps.Issuer,
		defaultTTL:      deps.DefaultTTL,
		pollInterval:    deps.PollInterval,
		callbackTimeout: timeout,
		logger:          deps.Logger,
	}
}

// notifyClient runs the OP→RP callback for ping- and push-mode clients
// after a terminal transition. The call is detached from the user's
// request context (so closing the browser does not cancel the ping)
// with its own short timeout. Failures are logged but do not roll back
// the OP-side state: ping clients can still poll /oidc/token, and the
// CIBARequest stays in its terminal state regardless.
func (h *CIBAHandler) notifyClient(authReqID string, req *domain.CIBARequest) {
	if h.callback == nil || req.ClientNotificationToken == "" {
		return
	}

	client, err := h.clients.GetByClientID(context.Background(), req.ClientID)
	if err != nil {
		h.logger.Error("ciba callback: lookup client", "err", err, "client_id", req.ClientID)
		return
	}

	if client.BackchannelTokenDeliveryMode == nil {
		return
	}
	if *client.BackchannelTokenDeliveryMode != domain.CIBADeliveryPing &&
		*client.BackchannelTokenDeliveryMode != domain.CIBADeliveryPush {
		// poll clients are not notified — the RP polls /oidc/token.
		return
	}
	if client.ClientNotificationEndpoint == nil || *client.ClientNotificationEndpoint == "" {
		h.logger.Warn("ciba callback: client has delivery mode but no endpoint",
			"client_id", client.ClientID, "mode", *client.BackchannelTokenDeliveryMode)
		return
	}

	// Push-mode bodies (tokens) land in phase 20. For now the body is
	// the same ping shape — push clients fall back to polling /token,
	// which still works.
	ctx, cancel := context.WithTimeout(context.Background(), h.callbackTimeout)
	defer cancel()

	if err := h.callback.Ping(ctx, *client.ClientNotificationEndpoint, req.ClientNotificationToken, authReqID); err != nil {
		h.logger.Error("ciba callback ping",
			"err", err,
			"client_id", client.ClientID,
			"endpoint", *client.ClientNotificationEndpoint,
		)
	}
}

// approveLoginBeginRequest is the body of POST /ciba/approve/login/begin.
type approveLoginBeginRequest struct {
	Token string `json:"t"`
}

// approveLoginBeginResponse mirrors the passkey service's BeginLogin
// shape (options + session id) so the page can call
// navigator.credentials.get directly.
type approveLoginBeginResponse struct {
	Options   json.RawMessage `json:"options"`
	SessionID string          `json:"session_id"`
}

// LoginBegin handles POST /ciba/approve/login/begin. It peeks the
// approval token (so an expired or already-decided request fails fast
// without burning a passkey prompt), then proxies BeginLogin to the
// passkey service.
func (h *CIBAHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	var req approveLoginBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"approval token is required")
		return
	}

	if _, err := h.approvalTksR.Peek(r.Context(), req.Token); err != nil {
		if errors.Is(err, domain.ErrApprovalTokenNotFound) {
			writeError(w, h.logger, http.StatusUnauthorized, "session_invalid",
				"this approval link has expired or already been used")
			return
		}
		h.logger.Error("approve: peek approval token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	begin, err := h.passkey.BeginLogin(r.Context())
	if err != nil {
		h.mapPasskeyError(w, "approve login begin", err)
		return
	}

	writeJSON(w, h.logger, http.StatusOK, approveLoginBeginResponse{
		Options:   begin.Options,
		SessionID: begin.SessionID,
	})
}

// approveRequest is the body of POST /ciba/approve.
type approveRequest struct {
	Token            string          `json:"t"`
	PasskeySessionID string          `json:"passkey_session_id"`
	Credential       json.RawMessage `json:"credential"`
}

// ApproveSubmit handles POST /ciba/approve. The flow:
//  1. consume the approval token (single-use)
//  2. load the CIBARequest the token refers to
//  3. broker CompleteLogin to the passkey service
//  4. map the returned passkey_user_id back to an op_user
//  5. verify that op_user matches the one /bc-authorize resolved
//     (PRD §7's login_hint match — blocks an attacker who stole the URL
//     from authorizing the request with their own passkey)
//  6. transition the CIBARequest to approved
func (h *CIBAHandler) ApproveSubmit(w http.ResponseWriter, r *http.Request) {
	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"request body is not valid JSON")
		return
	}
	if req.Token == "" || req.PasskeySessionID == "" || len(req.Credential) == 0 {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"t, passkey_session_id, and credential are required")
		return
	}

	authReqID, err := h.approvalTksC.Consume(r.Context(), req.Token)
	if errors.Is(err, domain.ErrApprovalTokenNotFound) {
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid",
			"approval link expired or already used")
		return
	}
	if err != nil {
		h.logger.Error("approve: consume approval token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	cibaReq, err := h.cibaRequestsR.Get(r.Context(), authReqID)
	if errors.Is(err, domain.ErrCIBARequestNotFound) {
		writeError(w, h.logger, http.StatusGone, "request_expired",
			"the underlying request has expired")
		return
	}
	if err != nil {
		h.logger.Error("approve: load ciba request", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}
	if cibaReq.Status != domain.CIBAStatusPending {
		writeError(w, h.logger, http.StatusConflict, "already_decided",
			"this request is no longer pending")
		return
	}

	complete, err := h.passkey.CompleteLogin(r.Context(), passkey.CompleteLoginRequest{
		SessionID:  req.PasskeySessionID,
		Credential: req.Credential,
	})
	if err != nil {
		h.mapPasskeyError(w, "approve login complete", err)
		return
	}

	passkeyUserID, err := uuid.Parse(complete.UserID)
	if err != nil {
		h.logger.Error("approve: parse passkey user_id", "err", err, "raw", complete.UserID)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable",
			"passkey service returned an invalid user_id")
		return
	}

	user, err := h.usersByPasskey.GetByPasskeyUserID(r.Context(), passkeyUserID)
	if errors.Is(err, domain.ErrOPUserNotFound) {
		writeError(w, h.logger, http.StatusForbidden, "user_mismatch",
			"this passkey is not linked to an account on this provider")
		return
	}
	if err != nil {
		h.logger.Error("approve: lookup op_user", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if user.ID != cibaReq.OPUserID {
		// The asserted passkey belongs to a different op_user than the
		// one the original /bc-authorize resolved from login_hint. This
		// is the spec's "different-user-took-over" attack — reject hard
		// and never reveal which user the request was meant for.
		h.logger.Warn("approve: user mismatch",
			"expected_op_user_id", cibaReq.OPUserID,
			"asserted_op_user_id", user.ID,
			"auth_req_id", authReqID,
		)
		writeError(w, h.logger, http.StatusForbidden, "user_mismatch",
			"this passkey does not match the requested user")
		return
	}

	if err := h.cibaRequestsT.Approve(r.Context(), authReqID, time.Now()); err != nil {
		if errors.Is(err, domain.ErrCIBANotPending) {
			writeError(w, h.logger, http.StatusConflict, "already_decided",
				"this request is no longer pending")
			return
		}
		if errors.Is(err, domain.ErrCIBARequestNotFound) {
			writeError(w, h.logger, http.StatusGone, "request_expired",
				"the underlying request has expired")
			return
		}
		h.logger.Error("approve: transition ciba request", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.notifyClient(authReqID, cibaReq)

	w.WriteHeader(http.StatusNoContent)
}

// denyRequest is the body of POST /ciba/deny.
type denyRequest struct {
	Token string `json:"t"`
}

// Deny handles POST /ciba/deny. Denial does not require a passkey
// ceremony — anyone holding the approval URL can decline (the same
// person who could have approved). The token is consumed so a deny
// cannot be undone, and the CIBARequest transitions to denied so the
// polling RP gets access_denied.
func (h *CIBAHandler) Deny(w http.ResponseWriter, r *http.Request) {
	var req denyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request",
			"approval token is required")
		return
	}

	authReqID, err := h.approvalTksC.Consume(r.Context(), req.Token)
	if errors.Is(err, domain.ErrApprovalTokenNotFound) {
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid",
			"approval link expired or already used")
		return
	}
	if err != nil {
		h.logger.Error("deny: consume approval token", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if err := h.cibaRequestsT.Deny(r.Context(), authReqID, time.Now()); err != nil {
		if errors.Is(err, domain.ErrCIBANotPending) {
			writeError(w, h.logger, http.StatusConflict, "already_decided",
				"this request is no longer pending")
			return
		}
		if errors.Is(err, domain.ErrCIBARequestNotFound) {
			writeError(w, h.logger, http.StatusGone, "request_expired",
				"the underlying request has expired")
			return
		}
		h.logger.Error("deny: transition ciba request", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
		return
	}

	if cibaReq, err := h.cibaRequestsR.Get(r.Context(), authReqID); err == nil {
		h.notifyClient(authReqID, cibaReq)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *CIBAHandler) mapPasskeyError(w http.ResponseWriter, op string, err error) {
	if serr, ok := errors.AsType[*passkey.ErrService](err); ok {
		switch serr.Code {
		case "session_invalid":
			writeError(w, h.logger, http.StatusUnauthorized, "session_invalid", "passkey session expired")
		case "credential_not_found", "no_credential":
			writeError(w, h.logger, http.StatusForbidden, "user_mismatch",
				"this passkey is not registered with the passkey service")
		case "invalid_request", "attestation_rejected":
			writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "passkey ceremony failed")
		default:
			h.logger.Warn("passkey "+op, "status", serr.Status, "code", serr.Code)
			writeError(w, h.logger, http.StatusBadGateway, "service_unavailable",
				"passkey service returned an error")
		}
		return
	}

	switch {
	case errors.Is(err, passkey.ErrServiceUnavailable),
		errors.Is(err, passkey.ErrTransport):
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable",
			"could not reach passkey service")
	default:
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "server_error", "")
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
