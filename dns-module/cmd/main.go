package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/jzap/dns-module/plugin/shieldproxy"
)

func main() {
	// Initialize zerolog with human-friendly console output in dev, JSON in prod
	logLevel := getEnv("LOG_LEVEL", "info")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	if getEnv("LOG_FORMAT", "json") == "console" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	log.Info().Msg("JZap DNS module starting")

	// Load configuration from environment
	listenAddr := getEnv("DNS_LISTEN_ADDR", ":5353")
	metricsAddr := getEnv("DNS_METRICS_ADDR", ":9092")
	redisAddr := getEnv("REDIS_ADDR", "redis:6379")

	responsesPerSecond, _ := strconv.Atoi(getEnv("RRL_RESPONSES_PER_SECOND", "5"))
	windowSeconds, _ := strconv.Atoi(getEnv("RRL_WINDOW_SECONDS", "1"))
	slipRatio, _ := strconv.ParseFloat(getEnv("RRL_SLIP_RATIO", "2.0"), 64)
	nxdomainThreshold, _ := strconv.Atoi(getEnv("RRL_NXDOMAIN_THRESHOLD", "100"))

	rrlConfig := shieldproxy.RRLConfig{
		ResponsesPerSecond: responsesPerSecond,
		WindowSeconds:      windowSeconds,
		SlipRatio:          slipRatio,
		NXDomainThreshold:  nxdomainThreshold,
	}

	// Initialize the shieldproxy plugin
	plugin, err := shieldproxy.Setup(redisAddr, rrlConfig)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize shieldproxy plugin")
	}

	log.Info().
		Str("listen", listenAddr).
		Str("redis", redisAddr).
		Int("rrl_rps", responsesPerSecond).
		Msg("Configuration loaded")

	// Create DNS handler that delegates to the shieldproxy plugin
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		ctx := context.Background()
		rcode, err := plugin.ServeDNS(ctx, w, r)
		if err != nil {
			log.Error().Err(err).Int("rcode", rcode).Msg("Error handling DNS query")
		}
	})

	// Start UDP DNS server
	udpServer := &dns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: handler,
	}

	// Start TCP DNS server
	tcpServer := &dns.Server{
		Addr:    listenAddr,
		Net:     "tcp",
		Handler: handler,
	}

	// Start Prometheus metrics endpoint
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Info().Str("addr", metricsAddr).Msg("Prometheus metrics server starting")
		if err := http.ListenAndServe(metricsAddr, mux); err != nil {
			log.Fatal().Err(err).Msg("Metrics server failed")
		}
	}()

	// Start DNS servers in goroutines
	go func() {
		log.Info().Str("addr", listenAddr).Str("net", "udp").Msg("DNS server starting")
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("UDP DNS server failed")
		}
	}()

	go func() {
		log.Info().Str("addr", listenAddr).Str("net", "tcp").Msg("DNS server starting")
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("TCP DNS server failed")
		}
	}()

	log.Info().Msg("JZap DNS module is running")

	// Graceful shutdown on SIGTERM/SIGINT
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	s := <-sig

	log.Info().Str("signal", s.String()).Msg("Received shutdown signal")

	// Shutdown DNS servers
	if err := udpServer.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down UDP server")
	}
	if err := tcpServer.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down TCP server")
	}

	// Close Redis connection
	if err := plugin.RedisClient.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing Redis connection")
	}

	log.Info().Msg("JZap DNS module stopped")
}

// getEnv returns the value of an environment variable or a default value.
func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func init() {
	// Ensure clean startup message
	fmt.Fprintln(os.Stderr, "JZap DNS Module — Standalone Mode")
}
