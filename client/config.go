package client

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Backends []BackendConfig `yaml:"backends"`
}

type HealthCheckConfig struct {
	Enabled           bool `yaml:"enabled"`
	InactivityTimeout int  `yaml:"inactivityTimeout"`
	PongTimeout       int  `yaml:"pongTimeout"`
}

type BackendConfig struct {
	Name         string            `yaml:"name"`
	Hostname     string            `yaml:"hostname"`
	NexusAddress string            `yaml:"nexusAddress"`
	AuthToken    string            `yaml:"authToken"`
	PortMappings map[int]string    `yaml:"portMappings"`
	HealthChecks HealthCheckConfig `yaml:"healthChecks"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml from %s: %w", path, err)
	}

	// Validation and setting defaults
	if len(cfg.Backends) == 0 {
		return nil, fmt.Errorf("no backends defined in config")
	}
	for i := range cfg.Backends {
		b := &cfg.Backends[i]
		if b.Name == "" {
			return nil, fmt.Errorf("backend #%d: name is required", i+1)
		}
		if b.Hostname == "" {
			return nil, fmt.Errorf("backend '%s': hostname is required", b.Name)
		}
		if b.NexusAddress == "" {
			return nil, fmt.Errorf("backend '%s': nexusAddress is required", b.Name)
		}
		if b.AuthToken == "" {
			return nil, fmt.Errorf("backend '%s': authToken is required", b.Name)
		}
		if len(b.PortMappings) == 0 {
			return nil, fmt.Errorf("backend '%s': at least one portMapping is required", b.Name)
		}
		if b.HealthChecks.Enabled {
			if b.HealthChecks.InactivityTimeout <= 0 {
				b.HealthChecks.InactivityTimeout = 60 // Default
			}
			if b.HealthChecks.PongTimeout <= 0 {
				b.HealthChecks.PongTimeout = 5 // Default
			}
		}
	}

	return &cfg, nil
}
