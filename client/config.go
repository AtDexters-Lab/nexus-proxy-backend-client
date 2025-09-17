package client

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/net/idna"
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
	Name           string              `yaml:"name"`
	Hostname       string              `yaml:"hostname"`
	Hostnames      []string            `yaml:"hostnames"`
	NexusAddresses []string            `yaml:"nexusAddresses"`
	AuthToken      string              `yaml:"authToken"`
	PortMappings   map[int]PortMapping `yaml:"portMappings"`
	HealthChecks   HealthCheckConfig   `yaml:"healthChecks"`
}

type wildcardRoute struct {
	pattern string
	suffix  string
	target  string
}

type PortMapping struct {
	Default string            `yaml:"default"`
	Hosts   map[string]string `yaml:"hosts"`
	wild    []wildcardRoute   `yaml:"-"`
}

func (pm *PortMapping) finalize() error {
	pm.Default = strings.TrimSpace(pm.Default)

	if len(pm.Hosts) == 0 {
		pm.Hosts = nil
		pm.wild = nil
		return nil
	}

	exacts := make(map[string]string, len(pm.Hosts))
	var wildcards []wildcardRoute
	for rawPattern, target := range pm.Hosts {
		target = strings.TrimSpace(target)
		if target == "" {
			return fmt.Errorf("port mapping override '%s' has empty target", rawPattern)
		}
		normalizedPattern := normalizeHostnameOrWildcard(rawPattern)
		if normalizedPattern == "" {
			return fmt.Errorf("invalid hostname pattern '%s' in port mapping", rawPattern)
		}
		if strings.HasPrefix(normalizedPattern, "*.") {
			suffix := normalizedPattern[1:] // includes leading dot
			wildcards = append(wildcards, wildcardRoute{
				pattern: normalizedPattern,
				suffix:  suffix,
				target:  target,
			})
		} else {
			exacts[normalizedPattern] = target
		}
	}

	sort.SliceStable(wildcards, func(i, j int) bool {
		return len(wildcards[i].suffix) > len(wildcards[j].suffix)
	})

	pm.Hosts = exacts
	pm.wild = wildcards
	return nil
}

func (pm PortMapping) Resolve(hostname string) (string, bool) {
	if hostname != "" {
		host := normalizeHostname(hostname)
		if host != "" {
			if pm.Hosts != nil {
				if target, ok := pm.Hosts[host]; ok {
					return target, true
				}
				for _, wc := range pm.wild {
					if matchesWildcard(host, wc.suffix) {
						return wc.target, true
					}
				}
			}
		}
	}
	if pm.Default != "" {
		return pm.Default, true
	}
	return "", false
}

func matchesWildcard(host, suffix string) bool {
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	if label == "" {
		return false
	}
	return !strings.Contains(label, ".")
}

var idnaLookup = idna.Lookup

func normalizeHostname(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	ascii, err := idnaLookup.ToASCII(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(ascii)
}

func normalizeHostnameOrWildcard(raw string) string {
	pattern := strings.TrimSpace(raw)
	if pattern == "" {
		return ""
	}
	if strings.HasPrefix(pattern, "*.") {
		normalized := normalizeHostname(pattern[2:])
		if normalized == "" {
			return ""
		}
		return "*." + normalized
	}
	return normalizeHostname(pattern)
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
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
		if len(b.Hostnames) == 0 {
			if b.Hostname != "" {
				b.Hostnames = []string{b.Hostname}
			}
		}
		if len(b.Hostnames) == 0 {
			return nil, fmt.Errorf("backend '%s': at least one hostname is required", b.Name)
		}
		normalized := make([]string, 0, len(b.Hostnames))
		seen := make(map[string]struct{}, len(b.Hostnames))
		for _, rawHost := range b.Hostnames {
			host := normalizeHostname(rawHost)
			if host == "" {
				return nil, fmt.Errorf("backend '%s': invalid hostname '%s'", b.Name, rawHost)
			}
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			normalized = append(normalized, host)
		}
		b.Hostnames = normalized
		b.Hostname = normalized[0]
		if len(b.NexusAddresses) == 0 {
			return nil, fmt.Errorf("backend '%s': nexusAddresses is required", b.Name)
		}
		if b.AuthToken == "" {
			return nil, fmt.Errorf("backend '%s': authToken is required", b.Name)
		}
		if len(b.PortMappings) == 0 {
			return nil, fmt.Errorf("backend '%s': at least one portMapping is required", b.Name)
		}
		for port, mapping := range b.PortMappings {
			if err := mapping.finalize(); err != nil {
				return nil, fmt.Errorf("backend '%s': port %d: %w", b.Name, port, err)
			}
			if mapping.Default == "" && len(mapping.Hosts) == 0 && len(mapping.wild) == 0 {
				return nil, fmt.Errorf("backend '%s': port %d: port mapping must specify a default or host overrides", b.Name, port)
			}
			b.PortMappings[port] = mapping
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
