package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rdaniel1105/go-oidc-provider/internal/api/handler"
	"github.com/rdaniel1105/go-oidc-provider/internal/config"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	keys, err := oidc.NewKeyStore(cfg.KeysDir, logger)
	if err != nil {
		logger.Error("key store init failed", "err", err)
		os.Exit(1)
	}

	discoveryDoc := oidc.NewDiscoveryDocument(cfg.Issuer)
	discovery := handler.NewDiscoveryHandler(keys, discoveryDoc, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", discovery.OpenIDConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", discovery.JWKS)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("server starting", "addr", cfg.HTTPAddr, "issuer", cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("server shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}
