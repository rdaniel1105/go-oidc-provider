// Package api wires HTTP handlers to a chi router. The router builder is
// the single place where the URL surface is declared; handlers themselves
// know nothing about routing.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/rdaniel1105/go-oidc-provider/internal/api/handler"
	"github.com/rdaniel1105/go-oidc-provider/internal/api/middleware"
)

// Deps bundles the collaborators the API needs to satisfy its handlers.
// Adding a new endpoint that needs a new collaborator means adding a
// field here, not threading values through the call site.
type Deps struct {
	// Logger receives one structured line per request.
	Logger *slog.Logger
	// Discovery serves the well-known endpoints.
	Discovery *handler.DiscoveryHandler
	// User serves the signup endpoints.
	User *handler.UserHandler
	// Authorize serves the auth-code flow endpoints.
	Authorize *handler.AuthorizeHandler
	// Token serves the OAuth/OIDC token endpoint.
	Token *handler.TokenHandler
	// UserInfo serves the Bearer-protected OIDC userinfo endpoint.
	UserInfo *handler.UserInfoHandler
}

// New builds the chi router. /health and /health/ready live at the root
// for load balancers and orchestrators; the OIDC well-known endpoints
// live at /.well-known per spec; everything else is grouped by feature.
func New(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(middleware.RequestLogger(deps.Logger))
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	r.Get("/.well-known/openid-configuration", deps.Discovery.OpenIDConfiguration)
	r.Get("/.well-known/jwks.json", deps.Discovery.JWKS)

	r.Route("/users", func(r chi.Router) {
		r.Post("/", deps.User.Begin)
		r.Post("/complete", deps.User.Complete)
	})

	r.Route("/oidc", func(r chi.Router) {
		r.Get("/authorize", deps.Authorize.Authorize)
		r.Post("/authorize/login/begin", deps.Authorize.LoginBegin)
		r.Post("/authorize/login/complete", deps.Authorize.LoginComplete)
		r.Post("/token", deps.Token.Token)
		r.Get("/userinfo", deps.UserInfo.UserInfo)
	})

	return r
}
