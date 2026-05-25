package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/rdaniel1105/go-oidc-provider/internal/domain"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
)

// signupStore captures only the bits of the Redis signup-state store that
// the user handler needs, so tests can inject an in-memory fake.
type signupStore interface {
	Save(ctx context.Context, sessionID string, state domain.SignupState) error
	Consume(ctx context.Context, sessionID string) (domain.SignupState, error)
}

// opUserCreator captures only the create-path of the Postgres op_user
// store. The handler does not list, update, or delete op_user rows.
type opUserCreator interface {
	Create(ctx context.Context, u *domain.OPUser) (*domain.OPUser, error)
}

// passkeyClient is the subset of internal/passkey.Client the handler
// drives. Defining it as an interface keeps the HTTP boundary mockable
// without spinning up a fake passkey service in unit tests.
type passkeyClient interface {
	BeginRegister(ctx context.Context, req passkey.BeginRegisterRequest) (passkey.BeginRegisterResponse, error)
	CompleteRegister(ctx context.Context, req passkey.CompleteRegisterRequest) (passkey.CompleteRegisterResponse, error)
}

// UserHandler implements POST /users (begin signup) and POST /users/complete
// (finalize signup). The op_user row is born at /complete only, after the
// authenticator has proven itself — abandoned ceremonies leave no trace.
type UserHandler struct {
	passkey passkeyClient
	signups signupStore
	users   opUserCreator
	logger  *slog.Logger
}

// NewUserHandler returns a UserHandler bound to the given collaborators.
func NewUserHandler(p passkeyClient, signups signupStore, users opUserCreator, logger *slog.Logger) *UserHandler {
	return &UserHandler{passkey: p, signups: signups, users: users, logger: logger}
}

// beginRequest is the body of POST /users.
type beginRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	PhoneE164   string `json:"phone_e164,omitempty"`
}

// beginResponse is the body of a successful POST /users. It forwards the
// passkey-side options + session_id verbatim so the browser can call
// navigator.credentials.create without an extra round-trip.
type beginResponse struct {
	// Options is the PublicKeyCredentialCreationOptions wire payload
	// produced by the passkey service.
	Options json.RawMessage `json:"options"`
	// SessionID is the value the browser must submit at POST /users/complete.
	SessionID string `json:"session_id"`
}

// Begin handles POST /users. It validates the form input, asks the passkey
// service to start a registration ceremony, persists the form state in
// Redis keyed by the returned session_id, and forwards the WebAuthn
// options to the browser.
func (h *UserHandler) Begin(w http.ResponseWriter, r *http.Request) {
	var req beginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}

	email := strings.TrimSpace(strings.ToLower(req.Email))
	displayName := strings.TrimSpace(req.DisplayName)
	phone := strings.TrimSpace(req.PhoneE164)

	if email == "" || !strings.Contains(email, "@") {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "email is required and must look like an address")
		return
	}
	if displayName == "" {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "display_name is required")
		return
	}
	if phone != "" && !looksLikeE164(phone) {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "phone_e164 must be in E.164 format (e.g. +573001234567)")
		return
	}

	begin, err := h.passkey.BeginRegister(r.Context(), passkey.BeginRegisterRequest{
		Username:    email,
		DisplayName: displayName,
	})
	if err != nil {
		h.mapPasskeyError(w, "begin register", err)
		return
	}

	state := domain.SignupState{Email: email, DisplayName: displayName}
	if phone != "" {
		state.PhoneE164 = &phone
	}

	if err := h.signups.Save(r.Context(), begin.SessionID, state); err != nil {
		h.logger.Error("signup save", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	writeJSON(w, h.logger, http.StatusOK, beginResponse{
		Options:   begin.Options,
		SessionID: begin.SessionID,
	})
}

// completeRequest is the body of POST /users/complete.
type completeRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

// completeResponse is the body of a successful POST /users/complete. The
// caller receives the new op_user id (the value that will appear as the
// `sub` claim in future ID tokens) and the passkey-side join key for
// transparency.
type completeResponse struct {
	OPUserID      uuid.UUID `json:"op_user_id"`
	PasskeyUserID string    `json:"passkey_user_id"`
}

// Complete handles POST /users/complete. It consumes the signup state,
// forwards the assertion to the passkey service, and persists the op_user
// row only after both halves succeed.
func (h *UserHandler) Complete(w http.ResponseWriter, r *http.Request) {
	var req completeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}

	if req.SessionID == "" || len(req.Credential) == 0 {
		writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "session_id and credential are required")
		return
	}

	state, err := h.signups.Consume(r.Context(), req.SessionID)
	if errors.Is(err, domain.ErrSignupStateNotFound) {
		writeError(w, h.logger, http.StatusUnauthorized, "session_invalid", "signup session expired or already consumed")
		return
	}
	if err != nil {
		h.logger.Error("signup consume", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
		return
	}

	complete, err := h.passkey.CompleteRegister(r.Context(), passkey.CompleteRegisterRequest{
		SessionID:  req.SessionID,
		Credential: req.Credential,
	})
	if err != nil {
		h.mapPasskeyError(w, "complete register", err)
		return
	}

	passkeyUserID, err := uuid.Parse(complete.UserID)
	if err != nil {
		h.logger.Error("complete register: parse user_id", "err", err, "raw", complete.UserID)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable", "passkey service returned an invalid user_id")
		return
	}

	user, err := h.users.Create(r.Context(), &domain.OPUser{
		Email:         state.Email,
		DisplayName:   state.DisplayName,
		PhoneE164:     state.PhoneE164,
		PasskeyUserID: passkeyUserID,
	})
	if err != nil {
		h.mapCreateError(w, err)
		return
	}

	writeJSON(w, h.logger, http.StatusCreated, completeResponse{
		OPUserID:      user.ID,
		PasskeyUserID: complete.UserID,
	})
}

func (h *UserHandler) mapPasskeyError(w http.ResponseWriter, op string, err error) {
	var serr *passkey.ServiceError
	switch {
	case errors.As(err, &serr):
		switch serr.Code {
		case "username_taken":
			writeError(w, h.logger, http.StatusConflict, "email_taken", "an account with this email already exists")
		case "session_invalid":
			writeError(w, h.logger, http.StatusUnauthorized, "session_invalid", "the passkey ceremony session is no longer valid")
		case "attestation_rejected", "invalid_request":
			writeError(w, h.logger, http.StatusBadRequest, "invalid_request", "passkey ceremony failed")
		default:
			h.logger.Warn("passkey "+op, "status", serr.Status, "code", serr.Code)
			writeError(w, h.logger, http.StatusBadGateway, "service_unavailable", "passkey service returned an error")
		}
	case errors.Is(err, passkey.ErrServiceUnavailable):
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable", "passkey service is unavailable")
	case errors.Is(err, passkey.ErrTransport):
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable", "could not reach passkey service")
	default:
		h.logger.Error("passkey "+op, "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
	}
}

func (h *UserHandler) mapCreateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrEmailTaken):
		writeError(w, h.logger, http.StatusConflict, "email_taken", "an account with this email already exists")
	case errors.Is(err, domain.ErrPhoneTaken):
		writeError(w, h.logger, http.StatusConflict, "phone_taken", "an account with this phone already exists")
	case errors.Is(err, domain.ErrPasskeyUserIDTaken):
		// Two op_users would point at the same passkey user — only
		// possible if the passkey service handed us a colliding user_id.
		// Surfacing it as a 502 (and not 409) communicates that the
		// failure is upstream, not user-driven.
		h.logger.Error("op_user create: passkey_user_id collision", "err", err)
		writeError(w, h.logger, http.StatusBadGateway, "service_unavailable", "passkey service returned a duplicate user_id")
	default:
		h.logger.Error("op_user create", "err", err)
		writeError(w, h.logger, http.StatusInternalServerError, "internal_error", "")
	}
}

// looksLikeE164 is a sanity check, not a strict validator: starts with '+'
// and the remainder is 8-15 digits per ITU E.164. A wrong country code
// will still pass this and is caught downstream by the notifier when it
// fails to deliver.
func looksLikeE164(s string) bool {
	if len(s) < 9 || len(s) > 16 || s[0] != '+' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
