package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPortMappingResolveDefault(t *testing.T) {
	pm := PortMapping{Default: "localhost:8080"}
	if err := pm.finalize(); err != nil {
		t.Fatalf("unexpected finalize error: %v", err)
	}

	addr, ok := pm.Resolve("app.example.com")
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if addr != "localhost:8080" {
		t.Fatalf("expected default target, got %s", addr)
	}
}

func TestPortMappingResolveExactOverride(t *testing.T) {
	pm := PortMapping{
		Default: "localhost:8080",
		Hosts: map[string]string{
			"api.example.com": "localhost:9090",
		},
	}
	if err := pm.finalize(); err != nil {
		t.Fatalf("unexpected finalize error: %v", err)
	}

	addr, ok := pm.Resolve("API.EXAMPLE.COM")
	if !ok {
		t.Fatal("expected resolution to succeed")
	}
	if addr != "localhost:9090" {
		t.Fatalf("expected override target, got %s", addr)
	}
}

func TestPortMappingResolveWildcard(t *testing.T) {
	pm := PortMapping{
		Default: "localhost:8080",
		Hosts: map[string]string{
			"*.example.com": "localhost:7070",
		},
	}
	if err := pm.finalize(); err != nil {
		t.Fatalf("unexpected finalize error: %v", err)
	}

	tests := []struct {
		host     string
		wantOK   bool
		wantAddr string
	}{
		{"foo.example.com", true, "localhost:7070"},
		{"foo.bar.example.com", true, "localhost:8080"},
		{"example.com", true, "localhost:8080"},
	}

	for _, tc := range tests {
		addr, ok := pm.Resolve(tc.host)
		if ok != tc.wantOK {
			t.Fatalf("host %s: expected ok=%v, got %v", tc.host, tc.wantOK, ok)
		}
		if !ok {
			continue
		}
		if addr != tc.wantAddr {
			t.Fatalf("host %s: expected addr=%s, got %s", tc.host, tc.wantAddr, addr)
		}
	}

	// host without matching override but no default should fail
	pmNoDefault := PortMapping{
		Hosts: map[string]string{
			"*.example.com": "localhost:7070",
		},
	}
	if err := pmNoDefault.finalize(); err != nil {
		t.Fatalf("unexpected finalize error: %v", err)
	}
	if _, ok := pmNoDefault.Resolve("unmatched.test"); ok {
		t.Fatal("expected resolution to fail without default")
	}
}

func TestLoadConfigRejectsUnknownPortMappingField(t *testing.T) {
	configYAML := `backends:
  - name: "dynamic"
    hostnames:
      - "example.com"
    nexusAddresses:
      - "wss://nexus.example.com/connect"
    attestation:
      command: "/usr/bin/true"
    portMappings:
      80:
        default: "localhost:8080"
        hostnames:
          "example.com": "localhost:9090"
`

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error due to unknown 'hostnames' field in port mapping")
	}
}

func TestLoadConfigRequiresAttestationMechanism(t *testing.T) {
	configYAML := `backends:
  - name: "missing"
    hostnames:
      - "example.com"
    nexusAddresses:
      - "wss://nexus.example.com/connect"
    portMappings:
      80:
        default: "localhost:8080"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error because no attestation command or secret configured")
	}
}

func TestLoadConfigAllowsHMACSecret(t *testing.T) {
	configYAML := `backends:
  - name: "hmac"
    hostnames:
      - "example.com"
    nexusAddresses:
      - "wss://nexus.example.com/connect"
    attestation:
      hmacSecret: "top-secret"
    portMappings:
      80:
        default: "localhost:8080"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got error: %v", err)
	}
	if cfg.Backends[0].Attestation.HMACSecret != "top-secret" {
		t.Fatalf("expected hmac secret to be preserved")
	}
	if cfg.Backends[0].Attestation.TokenTTLSeconds != 30 {
		t.Fatalf("expected default token TTL of 30 seconds, got %d", cfg.Backends[0].Attestation.TokenTTLSeconds)
	}
}
