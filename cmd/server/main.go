package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // sql.Open("pgx", ...) for golang-migrate

	"github.com/rdaniel1105/go-oidc-provider/internal/api"
	"github.com/rdaniel1105/go-oidc-provider/internal/api/handler"
	"github.com/rdaniel1105/go-oidc-provider/internal/config"
	"github.com/rdaniel1105/go-oidc-provider/internal/notifier"
	"github.com/rdaniel1105/go-oidc-provider/internal/oidc"
	"github.com/rdaniel1105/go-oidc-provider/internal/passkey"
	pgstore "github.com/rdaniel1105/go-oidc-provider/internal/store/postgres"
	redisstore "github.com/rdaniel1105/go-oidc-provider/internal/store/redis"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := applyMigrations(cfg.DatabaseURL); err != nil {
		logger.Error("migrations failed", "err", err)
		os.Exit(1)
	}

	pgPool, err := pgstore.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("postgres pool init failed", "err", err)
		os.Exit(1)
	}
	defer pgPool.Close()

	redisClient, err := redisstore.NewClient(ctx, cfg.RedisURL)
	if err != nil {
		logger.Error("redis client init failed", "err", err)
		os.Exit(1)
	}
	defer func() { _ = redisClient.Close() }()

	keys, err := oidc.NewKeyStore(cfg.KeysDir, logger)
	if err != nil {
		logger.Error("key store init failed", "err", err)
		os.Exit(1)
	}

	clientStore := pgstore.NewClientStore(pgPool)
	opUserStore := pgstore.NewOPUserStore(pgPool)
	refreshTokenStore := pgstore.NewRefreshTokenStore(pgPool)
	signupStore := redisstore.NewSignupStateStore(redisClient, cfg.ApprovalTokenTTL)
	authSessionStore := redisstore.NewAuthSessionStore(redisClient, cfg.ApprovalTokenTTL)
	authCodeStore := redisstore.NewAuthCodeStore(redisClient, cfg.AuthCodeTTL)
	cibaRequestStore := redisstore.NewCIBARequestStore(redisClient)
	approvalTokenStore := redisstore.NewApprovalTokenStore(redisClient, cfg.ApprovalTokenTTL)
	passkeyClient := passkey.New(cfg.PasskeyServiceURL)

	authDeviceNotifier, err := notifier.Build(cfg, logger)
	if err != nil {
		logger.Error("notifier build failed", "err", err)
		os.Exit(1)
	}

	discoveryDoc := oidc.NewDiscoveryDocument(cfg.Issuer)
	discoveryHandler := handler.NewDiscoveryHandler(keys, discoveryDoc, logger)
	userHandler := handler.NewUserHandler(passkeyClient, signupStore, opUserStore, logger)
	authorizeHandler := handler.NewAuthorizeHandler(
		clientStore, opUserStore, authSessionStore, authCodeStore, passkeyClient, logger,
	)
	tokenHandler := handler.NewTokenHandler(handler.TokenHandlerDeps{
		Clients:      clientStore,
		AuthCodes:    authCodeStore,
		Users:        opUserStore,
		Refresh:      refreshTokenStore,
		CIBA:         cibaRequestStore,
		Keys:         keys,
		Issuer:       cfg.Issuer,
		AccessTTL:    cfg.AccessTokenTTL,
		RefreshTTL:   cfg.RefreshTokenTTL,
		PollInterval: 5,
		Logger:       logger,
	})
	userInfoHandler := handler.NewUserInfoHandler(keys, opUserStore, cfg.Issuer, logger)
	cibaHandler := handler.NewCIBAHandler(handler.CIBAHandlerDeps{
		Clients:                  clientStore,
		Users:                    opUserStore,
		UsersByPasskey:           opUserStore,
		CIBARequests:             cibaRequestStore,
		CIBARequestsReader:       cibaRequestStore,
		CIBARequestsTransitioner: cibaRequestStore,
		ApprovalTokens:           approvalTokenStore,
		ApprovalTokensReader:     approvalTokenStore,
		ApprovalTokensConsumer:   approvalTokenStore,
		Passkey:                  passkeyClient,
		Notifier:                 authDeviceNotifier,
		Issuer:                   cfg.Issuer,
		DefaultTTL:               cfg.CIBARequestTTL,
		PollInterval:             5,
		Logger:                   logger,
	})

	router := api.New(api.Deps{
		Logger:    logger,
		Discovery: discoveryHandler,
		User:      userHandler,
		Authorize: authorizeHandler,
		Token:     tokenHandler,
		UserInfo:  userInfoHandler,
		CIBA:      cibaHandler,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}

// applyMigrations runs all pending embedded SQL migrations against the
// configured database. Idempotent — succeeds with ErrNoChange when there
// is nothing to apply.
func applyMigrations(dsn string) error {
	src, err := iofs.New(pgstore.MigrationsFS(), "migrations")
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open sql db: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	db, err := migratepg.WithInstance(sqlDB, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}

	mig, err := migrate.NewWithInstance("iofs", src, "postgres", db)
	if err != nil {
		return fmt.Errorf("migrate instance: %w", err)
	}

	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}

	return nil
}
