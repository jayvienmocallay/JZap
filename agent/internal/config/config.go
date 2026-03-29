package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds the JZap agent configuration.
type Config struct {
	ControlPlaneURL        string `yaml:"control_plane_url"  env:"JZAP_CONTROL_PLANE_URL"`
	SyncIntervalSeconds    int    `yaml:"sync_interval_seconds"  env:"JZAP_SYNC_INTERVAL_SECONDS"`
	TelemetryIntervalSeconds int  `yaml:"telemetry_interval_seconds" env:"JZAP_TELEMETRY_INTERVAL_SECONDS"`
	MetricsPort            int    `yaml:"metrics_port"       env:"JZAP_METRICS_PORT"`
	CertFile               string `yaml:"cert_file"          env:"JZAP_CERT_FILE"`
	KeyFile                string `yaml:"key_file"           env:"JZAP_KEY_FILE"`
	CAFile                 string `yaml:"ca_file"            env:"JZAP_CA_FILE"`
	FallbackBlocklistPath  string `yaml:"fallback_blocklist_path" env:"JZAP_FALLBACK_BLOCKLIST_PATH"`
}

// applyDefaults sets default values for fields that are zero-valued.
func (c *Config) applyDefaults() {
	if c.SyncIntervalSeconds == 0 {
		c.SyncIntervalSeconds = 30
	}
	if c.TelemetryIntervalSeconds == 0 {
		c.TelemetryIntervalSeconds = 10
	}
	if c.MetricsPort == 0 {
		c.MetricsPort = 9091
	}
	if c.FallbackBlocklistPath == "" {
		c.FallbackBlocklistPath = "/var/lib/jzap/fallback_blocklist.txt"
	}
}

// Load reads configuration from a YAML file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	cfg.applyDefaults()
	return cfg, nil
}

// LoadFromEnv reads configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		ControlPlaneURL:       os.Getenv("JZAP_CONTROL_PLANE_URL"),
		CertFile:              os.Getenv("JZAP_CERT_FILE"),
		KeyFile:               os.Getenv("JZAP_KEY_FILE"),
		CAFile:                os.Getenv("JZAP_CA_FILE"),
		FallbackBlocklistPath: os.Getenv("JZAP_FALLBACK_BLOCKLIST_PATH"),
	}

	if v := os.Getenv("JZAP_SYNC_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid JZAP_SYNC_INTERVAL_SECONDS: %w", err)
		}
		cfg.SyncIntervalSeconds = n
	}

	if v := os.Getenv("JZAP_TELEMETRY_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid JZAP_TELEMETRY_INTERVAL_SECONDS: %w", err)
		}
		cfg.TelemetryIntervalSeconds = n
	}

	if v := os.Getenv("JZAP_METRICS_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid JZAP_METRICS_PORT: %w", err)
		}
		cfg.MetricsPort = n
	}

	cfg.applyDefaults()
	return cfg, nil
}

// Validate checks that the configuration has all required fields.
func (c *Config) Validate() error {
	if c.ControlPlaneURL == "" {
		return fmt.Errorf("control_plane_url is required")
	}
	if c.SyncIntervalSeconds < 1 {
		return fmt.Errorf("sync_interval_seconds must be >= 1, got %d", c.SyncIntervalSeconds)
	}
	if c.TelemetryIntervalSeconds < 1 {
		return fmt.Errorf("telemetry_interval_seconds must be >= 1, got %d", c.TelemetryIntervalSeconds)
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return fmt.Errorf("metrics_port must be between 1 and 65535, got %d", c.MetricsPort)
	}
	return nil
}
