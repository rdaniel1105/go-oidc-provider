// Package middleware holds the cross-cutting HTTP middlewares used by the
// router: structured request logging today, with RP-session enforcement
// landing alongside the auth-code flow in a later phase.
package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// RequestLogger returns a middleware that emits one structured log line
// per request after the inner handler runs. It pairs with chi's
// middleware.RequestID upstream — the request id is pulled from context
// and included in every line so logs can be correlated.
//
// Health endpoints are high-volume and uninteresting in steady state, so
// the middleware skips them. Add more skips here, not at call sites.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skipLogging(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("remote_ip", r.RemoteAddr),
				slog.String("request_id", chimw.GetReqID(r.Context())),
			}

			level := slog.LevelInfo
			switch {
			case ww.Status() >= 500:
				level = slog.LevelError
			case ww.Status() >= 400:
				level = slog.LevelWarn
			}

			logger.LogAttrs(r.Context(), level, "http request", attrs...)
		})
	}
}

func skipLogging(path string) bool {
	return path == "/health" || path == "/health/ready"
}
