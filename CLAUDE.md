# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nexus Proxy Backend Client is a Go library and CLI tool that connects local services to the Nexus Proxy mesh via WebSocket. It relays TCP traffic between Nexus and local services, supporting multi-hostname routing, wildcard matching, and pluggable attestation.

## Commands

```bash
# Run the client
go run ./cmd/client -config config.yaml

# Run all tests
go test ./client/...

# Run specific test
go test ./client/... -run TestPortMappingResolve

# Format code
go fmt ./...

# Vet code
go vet ./...
```

## Architecture

### Core Components

**Client** (`client/client.go`) - Main connection lifecycle manager:
- Manages WebSocket connection to Nexus with reconnection logic
- Exponential backoff with jitter (5s base, 60s max, ±25%) for reconnection
- Linux netlink hooks for fast network recovery (`network_linux.go`)
- Spawns `readPump`, `writePump`, and `healthCheckPump` goroutines
- Stores active local connections in `sync.Map` keyed by UUID
- Per-connection write queues for non-blocking data relay
- Uses buffered channel for outbound message queue

**Configuration** (`client/config.go`) - YAML parsing and validation:
- `Config.LoadConfig(path)` loads and validates the config file
- Supports hostname normalization (IDNA) and wildcard matching (`*.example.com`)
- Port mappings support exact hostname overrides taking precedence over wildcards

**Attestation** (`client/attestation.go`) - Token generation:
- `TokenProvider` interface for pluggable token generation
- `CommandTokenProvider` executes external commands for JWT tokens
- `HMACTokenProvider` signs tokens locally using HS256
- Three stages: `handshake` (Stage 0), `attest` (Stage 1), `reauth`

**Options** (`client/options.go`) - Extensibility hooks:
- `WithConnectHandler()` for custom connection routing
- `WithTokenProvider()` for custom token generation
- Return `client.ErrNoRoute` to fall back to static port mappings

### Message Protocol

- **Text messages**: JSON control messages (handshake challenges, reauth)
- **Binary messages**:
  - `0x01` + 16-byte client ID + payload = data stream
  - `0x02` + JSON = control commands (connect/disconnect/ping/pong)

### Connection Lifecycle

1. `connectAndAuthenticate()`: Dial WebSocket, send Stage 0 token, receive challenge, send Stage 1 token with nonce
2. Start pumps: `readPump` receives from Nexus, `writePump` sends queued messages, `healthCheckPump` monitors idle connections
3. On `connect` command: create pending connection in `localConns`, spawn `establishLocalConnection` goroutine to dial asynchronously (buffers early data), then spawn `copyLocalToNexus` and `writeToLocal` goroutines
4. On `reauth_challenge`: generate and send Stage 3 token without interrupting streams
5. On session end: close all local connections (cannot be resumed across sessions)

### Library Integration

```go
router := func(ctx context.Context, req client.ConnectRequest) (net.Conn, error) {
    if strings.HasSuffix(req.Hostname, ".preview.example.com") {
        return net.Dial("tcp", "localhost:5080")
    }
    return nil, client.ErrNoRoute  // Fall back to YAML config
}
c, _ := client.New(cfg, client.WithConnectHandler(router))
go c.Start(ctx)
```

`ConnectRequest.IsTLS` indicates whether the original client negotiated HTTPS.

## Configuration

Key config fields in `config.yaml`:

- `hostnames`: FQDNs or wildcards this backend serves
- `attestation`: Either `command` (external) or `hmacSecret`/`hmacSecretFile` (built-in HS256)
- `portMappings`: Maps Nexus ports to local targets with optional hostname overrides
- `healthChecks`: Active ping/pong for connection liveness

Attestation command receives environment variables: `NEXUS_ATTESTATION_STAGE`, `NEXUS_SESSION_NONCE`, `NEXUS_BACKEND_NAME`, `NEXUS_HOSTNAMES`, `NEXUS_WEIGHT`.
