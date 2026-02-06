package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	cfg := loadConfig()
	log := newLogger(cfg.LogFormat)

	cache := NewDIDCache()
	resolver := NewPLCResolver(cache)
	verifier := NewPDSVerifier(resolver)

	relay := NewRelay(cfg.RelayURL(), resolver, verifier, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay.Run(ctx)

	handler := relay.Handler()

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Info("received signal, shutting down", "signal", sig)
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	if cfg.TLS {
		log.Info("starting relay with TLS", "domain", cfg.Domain, "addr", cfg.Addr)
		m := &autocert.Manager{
			Cache:      autocert.DirCache("certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
		}
		srv.TLSConfig = m.TLSConfig()
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	} else {
		log.Info("starting relay without TLS", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}

	log.Info("server stopped")
}

type Config struct {
	TLS       bool
	Domain    string
	Addr      string
	LogFormat string
}

func (c *Config) RelayURL() string {
	if c.TLS {
		return "wss://" + c.Domain
	}
	// For dev mode, construct from addr
	addr := c.Addr
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	return "ws://" + addr
}

func loadConfig() Config {
	cfg := Config{
		TLS:       envOrDefault("RELAY_TLS", "true") == "true",
		Domain:    os.Getenv("RELAY_DOMAIN"),
		LogFormat: envOrDefault("LOG_FORMAT", "json"),
	}

	if addr := os.Getenv("RELAY_ADDR"); addr != "" {
		cfg.Addr = addr
	} else if cfg.TLS {
		cfg.Addr = ":443"
	} else {
		cfg.Addr = ":8080"
	}

	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newLogger(format string) *slog.Logger {
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	return slog.New(handler)
}
