package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crubly/signer-backend/internal/api"
	"github.com/crubly/signer-backend/internal/apple"
	"github.com/crubly/signer-backend/internal/crypto"
	"github.com/crubly/signer-backend/internal/notify"
	"github.com/crubly/signer-backend/internal/store"
)

func main() {
	port := envOr("PORT", "8095")
	dsn := envOr("DATABASE_URL", "postgres://signer:signer@postgres:5432/signer?sslmode=disable")
	encKey := envOr("ENCRYPTION_KEY", "change-me-32-byte-secret-key-prod")
	jwtSecret := envOr("JWT_SECRET", encKey)
	dataDir := envOr("DATA_DIR", "/data")
	zsignBin := envOr("ZSIGN_BIN", "zsign")
	publicURL := os.Getenv("PUBLIC_URL")
	anisetteURL := envOr("ANISETTE_URL", "https://ani.sidestore.io")

	cipher := crypto.NewCipher(encKey)
	st, err := store.NewPostgres(dsn, cipher, publicURL, anisetteURL)
	if err != nil {
		log.Fatalf("postgres init failed: %v", err)
	}

	ap := apple.NewClient(anisetteURL)
	disp := notify.NewDispatcher(st)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go disp.Start(ctx)

	srv := api.NewServer(api.Config{
		DataDir:     dataDir,
		ZsignBin:    zsignBin,
		JWTSecret:   jwtSecret,
		PublicURL:   publicURL,
		AnisetteURL: anisetteURL,
	}, st, ap, disp)

	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("Signer backend listening on :%s", port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer sCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
