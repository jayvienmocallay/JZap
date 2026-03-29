package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/jzap/agent/internal/config"
	"github.com/jzap/agent/internal/fallback"
	"github.com/jzap/agent/internal/firewall"
	"github.com/jzap/agent/internal/sync"
	"github.com/jzap/agent/internal/telemetry"
)

func main() {
	configPath := flag.String("config", "/etc/jzap/config.yaml", "path to config.yaml")
	flag.Parse()

	// Handle "healthcheck" subcommand.
	if len(flag.Args()) > 0 && flag.Args()[0] == "healthcheck" {
		fmt.Println("JZap Agent healthcheck: OK")
		os.Exit(0)
	}

	// Initialize zerolog with JSON output to stdout.
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "jzap-agent").Logger()

	// Load configuration from YAML file, falling back to environment variables.
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to load config from file, trying environment variables")
		cfg, err = config.LoadFromEnv()
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to load config from environment")
		}
	}

	if err := cfg.Validate(); err != nil {
		logger.Fatal().Err(err).Msg("invalid configuration")
	}

	logger.Info().
		Str("control_plane_url", cfg.ControlPlaneURL).
		Int("sync_interval_s", cfg.SyncIntervalSeconds).
		Int("telemetry_interval_s", cfg.TelemetryIntervalSeconds).
		Int("metrics_port", cfg.MetricsPort).
		Msg("JZap Agent started")

	// Initialize nftables firewall manager.
	fw, err := firewall.New()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize firewall manager")
	}
	defer fw.Close()

	// Create fallback manager.
	fbManager := fallback.New(fw, cfg.FallbackBlocklistPath)

	// Cancellable context for background goroutines.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start blocklist sync goroutine.
	syncer := sync.New(
		cfg.ControlPlaneURL,
		time.Duration(cfg.SyncIntervalSeconds)*time.Second,
		fw,
	)
	go func() {
		if err := syncer.Start(ctx); err != nil {
			logger.Error().Err(err).Msg("blocklist syncer encountered an error, entering fallback mode")
			if fbErr := fbManager.EnterFallbackMode(); fbErr != nil {
				logger.Error().Err(fbErr).Msg("failed to enter fallback mode")
			}
		}
	}()

	// Start telemetry reporter goroutine.
	reporter := telemetry.New(
		cfg.ControlPlaneURL,
		time.Duration(cfg.TelemetryIntervalSeconds)*time.Second,
	)
	go reporter.Start(ctx)

	// Start Prometheus metrics HTTP server.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info().Str("addr", metricsAddr).Msg("Prometheus metrics server listening")
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("metrics server error")
		}
	}()

	// Wait for SIGTERM or SIGINT for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh

	logger.Info().Str("signal", sig.String()).Msg("JZap Agent shutting down")

	// Cancel background goroutines.
	cancel()

	// Shut down metrics server.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("metrics server shutdown error")
	}

	// Flush firewall rules.
	if err := fw.Flush(); err != nil {
		logger.Error().Err(err).Msg("failed to flush firewall rules on shutdown")
	}

	logger.Info().Msg("JZap Agent stopped")
}
