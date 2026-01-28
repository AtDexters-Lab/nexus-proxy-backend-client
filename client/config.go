package client

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

// Transport represents the network protocol for a connection.
// Valid values are "tcp" and "udp". The server sends this field in connect
// messages to indicate whether the client should dial a TCP or UDP connection
// to the local backend service.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// UDPRouteConfig defines a UDP port claim with optional flow idle timeout.
// FlowIdleTimeoutSeconds specifies how long the server waits before cleaning up
// an idle UDP flow. If nil, the server uses its default timeout. If set to 0,
// behavior depends on server implementation (typically uses default or no timeout).
type UDPRouteConfig struct {
	Port                   int  `yaml:"port"`
	FlowIdleTimeoutSeconds *int `yaml:"flowIdleTimeoutSeconds,omitempty"`
}

type Config struct {
	Backends []BackendConfig `yaml:"backends"`
}

type HealthCheckConfig struct {
	Enabled           bool `yaml:"enabled"`
	InactivityTimeout int  `yaml:"inactivityTimeout"`
	PongTimeout       int  `yaml:"pongTimeout"`
}

type AttestationConfig struct {
	Command                    string            `yaml:"command"`
	Args                       []string          `yaml:"args"`
	Env                        map[string]string `yaml:"env"`
	TimeoutSeconds             int               `yaml:"timeoutSeconds"`
	CacheHandshakeSeconds      int               `yaml:"cacheHandshakeSeconds"`
	HMACSecret                 string            `yaml:"hmacSecret"`
	HMACSecretFile             string            `yaml:"hmacSecretFile"`
	TokenTTLSeconds            int               `yaml:"tokenTTLSeconds"`
	HandshakeMaxAgeSeconds     int               `yaml:"handshakeMaxAgeSeconds"`
	ReauthIntervalSeconds      int               `yaml:"reauthIntervalSeconds"`
	ReauthGraceSeconds         int               `yaml:"reauthGraceSeconds"`
	MaintenanceGraceCapSeconds int               `yaml:"maintenanceGraceCapSeconds"`
	AuthorizerStatusURI        string            `yaml:"authorizerStatusUri"`
	PolicyVersion              string            `yaml:"policyVersion"`
}

type BackendConfig struct {
	Name           string              `yaml:"name"`
	Hostname       string              `yaml:"hostname"`
	Hostnames      []string            `yaml:"hostnames"`
	TCPPorts       []int               `yaml:"tcpPorts,omitempty"`
	UDPRoutes      []UDPRouteConfig    `yaml:"udpRoutes,omitempty"`
	NexusAddresses []string            `yaml:"nexusAddresses"`
	Weight         int                 `yaml:"weight"`
	Attestation    AttestationConfig   `yaml:"attestation"`
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

		// Validate and deduplicate TCPPorts (preserving original order)
		if len(b.TCPPorts) > 0 {
			seen := make(map[int]struct{})
			deduped := make([]int, 0, len(b.TCPPorts))
			for _, port := range b.TCPPorts {
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("backend '%s': invalid TCP port %d (must be 1-65535)", b.Name, port)
				}
				if _, exists := seen[port]; exists {
					continue
				}
				seen[port] = struct{}{}
				deduped = append(deduped, port)
			}
			b.TCPPorts = deduped
		}

		// Validate UDPRoutes
		seenUDPPorts := make(map[int]struct{})
		for j, route := range b.UDPRoutes {
			if route.Port < 1 || route.Port > 65535 {
				return nil, fmt.Errorf("backend '%s': invalid UDP port %d (must be 1-65535)", b.Name, route.Port)
			}
			if route.FlowIdleTimeoutSeconds != nil && *route.FlowIdleTimeoutSeconds < 0 {
				return nil, fmt.Errorf("backend '%s': udpRoutes[%d].flowIdleTimeoutSeconds cannot be negative", b.Name, j)
			}
			if _, exists := seenUDPPorts[route.Port]; exists {
				return nil, fmt.Errorf("backend '%s': duplicate UDP port %d in udpRoutes", b.Name, route.Port)
			}
			seenUDPPorts[route.Port] = struct{}{}
		}

		hasPortClaims := len(b.TCPPorts) > 0 || len(b.UDPRoutes) > 0

		// Allow backends without hostnames if they have port claims
		if len(b.Hostnames) == 0 && !hasPortClaims {
			return nil, fmt.Errorf("backend '%s': at least one hostname, tcpPort, or udpRoute is required", b.Name)
		}

		normalized := make([]string, 0, len(b.Hostnames))
		seen := make(map[string]struct{}, len(b.Hostnames))
		for _, rawHost := range b.Hostnames {
			// Reject hostnames that look like route keys
			if strings.HasPrefix(rawHost, "tcp:") || strings.HasPrefix(rawHost, "udp:") {
				return nil, fmt.Errorf("backend '%s': invalid hostname '%s' (cannot use route key format)", b.Name, rawHost)
			}
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
		if len(normalized) > 0 {
			b.Hostname = normalized[0]
		}
		if len(b.NexusAddresses) == 0 {
			return nil, fmt.Errorf("backend '%s': nexusAddresses is required", b.Name)
		}
		if b.Weight <= 0 {
			b.Weight = 1
		}
		hasCommand := strings.TrimSpace(b.Attestation.Command) != ""
		b.Attestation.HMACSecret = strings.TrimSpace(b.Attestation.HMACSecret)
		b.Attestation.HMACSecretFile = strings.TrimSpace(b.Attestation.HMACSecretFile)
		hasSecret := b.Attestation.HMACSecret != "" || b.Attestation.HMACSecretFile != ""
		if !hasCommand && !hasSecret {
			return nil, fmt.Errorf("backend '%s': attestation requires either command or hmacSecret(/File)", b.Name)
		}
		if b.Attestation.TimeoutSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.timeoutSeconds cannot be negative", b.Name)
		}
		if b.Attestation.TimeoutSeconds == 0 {
			b.Attestation.TimeoutSeconds = 15
		}
		if b.Attestation.CacheHandshakeSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.cacheHandshakeSeconds cannot be negative", b.Name)
		}
		if b.Attestation.TokenTTLSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.tokenTTLSeconds cannot be negative", b.Name)
		}
		if b.Attestation.TokenTTLSeconds == 0 {
			b.Attestation.TokenTTLSeconds = 30
		}
		if b.Attestation.HandshakeMaxAgeSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.handshakeMaxAgeSeconds cannot be negative", b.Name)
		}
		if b.Attestation.ReauthIntervalSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.reauthIntervalSeconds cannot be negative", b.Name)
		}
		if b.Attestation.ReauthGraceSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.reauthGraceSeconds cannot be negative", b.Name)
		}
		if b.Attestation.MaintenanceGraceCapSeconds < 0 {
			return nil, fmt.Errorf("backend '%s': attestation.maintenanceGraceCapSeconds cannot be negative", b.Name)
		}
		b.Attestation.AuthorizerStatusURI = strings.TrimSpace(b.Attestation.AuthorizerStatusURI)
		b.Attestation.PolicyVersion = strings.TrimSpace(b.Attestation.PolicyVersion)
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

		// Warn if claimed ports have no matching portMappings entry
		for _, port := range b.TCPPorts {
			if _, ok := b.PortMappings[port]; !ok {
				log.Printf("WARN: backend '%s': tcpPort %d has no matching portMapping entry", b.Name, port)
			}
		}
		for _, route := range b.UDPRoutes {
			if _, ok := b.PortMappings[route.Port]; !ok {
				log.Printf("WARN: backend '%s': udpRoute port %d has no matching portMapping entry", b.Name, route.Port)
			}
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
