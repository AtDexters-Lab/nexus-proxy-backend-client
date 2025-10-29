package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/AtDexters-Lab/nexus-proxy-backend-client/client"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the configuration file.")
	flag.Parse()

	cfg, err := client.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("FATAL: Error loading configuration: %v", err)
	}

	log.Printf("INFO: Starting Nexus Backend Client for %d configured services...", len(cfg.Backends))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Create and start a client instance for each configured backend.
	for _, backendCfg := range cfg.Backends {
		for _, nexusAddr := range backendCfg.NexusAddresses {
			wg.Add(1)
			go func(cfg client.ClientBackendConfig) {
				defer wg.Done()
				c, err := client.New(cfg)
				if err != nil {
					log.Printf("ERROR: Failed to construct client for backend %s targeting %s: %v", cfg.Name, cfg.NexusAddress, err)
					return
				}
				c.Start(ctx)
			}(client.ClientBackendConfig{
				Name:         backendCfg.Name,
				Hostnames:    append([]string(nil), backendCfg.Hostnames...),
				NexusAddress: nexusAddr,
				Weight:       backendCfg.Weight,
				Attestation: client.AttestationOptions{
					Command:                    backendCfg.Attestation.Command,
					Args:                       append([]string(nil), backendCfg.Attestation.Args...),
					Env:                        copyStringMap(backendCfg.Attestation.Env),
					Timeout:                    time.Duration(backendCfg.Attestation.TimeoutSeconds) * time.Second,
					CacheHandshake:             time.Duration(backendCfg.Attestation.CacheHandshakeSeconds) * time.Second,
					HMACSecret:                 backendCfg.Attestation.HMACSecret,
					HMACSecretFile:             backendCfg.Attestation.HMACSecretFile,
					TokenTTL:                   time.Duration(backendCfg.Attestation.TokenTTLSeconds) * time.Second,
					HandshakeMaxAgeSeconds:     backendCfg.Attestation.HandshakeMaxAgeSeconds,
					ReauthIntervalSeconds:      backendCfg.Attestation.ReauthIntervalSeconds,
					ReauthGraceSeconds:         backendCfg.Attestation.ReauthGraceSeconds,
					MaintenanceGraceCapSeconds: backendCfg.Attestation.MaintenanceGraceCapSeconds,
					AuthorizerStatusURI:        backendCfg.Attestation.AuthorizerStatusURI,
					PolicyVersion:              backendCfg.Attestation.PolicyVersion,
				},
				PortMappings: backendCfg.PortMappings,
				HealthChecks: backendCfg.HealthChecks,
			})
		}
	}

	// Wait for shutdown signal.
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	<-shutdownChan

	log.Println("INFO: Shutdown signal received. Stopping all clients...")
	cancel() // Signal all client goroutines to stop.

	wg.Wait() // Wait for all clients to finish cleaning up.
	log.Println("INFO: All clients have shut down gracefully. Exiting.")
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
