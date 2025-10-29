# Nexus Proxy - Reference Backend Client

This application is a reference implementation of a backend service client for the [Nexus Proxy Server](https://github.com/AtDexters-Lab/nexus-proxy-server).

It demonstrates how a local service can securely connect to the Nexus mesh and have traffic relayed to it for multiple hostnames and ports simultaneously. This project is structured as a library (`client` package) with a simple command-line wrapper (`cmd/client/main.go`), making it easy to integrate into your own applications.

## How it Works

1.  **Configuration Driven:** The client reads a `config.yaml` file to determine which services to expose.
2.  **Connects Outbound:** For each configured service, it initiates a WebSocket connection to a Nexus Proxy node.
3.  **Performs TPM attestation:** Immediately after connecting, it runs the configured attestation command to fetch a Stage&nbsp;0 “handshake” token, sends it, waits for Nexus to issue a `handshake_challenge`, then produces a Stage&nbsp;1 token that embeds the provided `session_nonce`.
4.  **Handles re-attestation:** Whenever Nexus pushes a `reauth_challenge`, the client reruns the attestation command (Stage&nbsp;`reauth`) and replies with the refreshed token without interrupting active streams.
5.  **Listens for Commands:** It listens for JSON control messages from the proxy, primarily `connect` and `disconnect` commands.
6.  **Active Health Checks:** The client actively monitors its connections. If a connection is idle for too long, it sends a `ping_client` message to the Nexus Proxy to verify the connection is still alive on the proxy side. If no `pong_client` is received, the client cleans up the local connection, preventing zombies.
7.  **Host-Aware Relaying:** `portMappings` can route by port, hostname, or single-label wildcard (e.g. `*.preview.example.com`), allowing one backend connection to front multiple virtual hosts.

## Configuration

The client is configured via a `config.yaml` file.
See [config.example.yaml](config.example.yaml).

Key fields:

- `hostnames`: list every FQDN (or `*.example.com` wildcard) this backend will serve. These must line up with the attestation claims issued by your authorizer.
- `attestation`: describes how tokens are produced—either by running an external command or, when `hmacSecret`/`hmacSecretFile` is provided, by signing locally with HS256 (see [Attestation Command Contract](#attestation-command-contract)).
- `weight`: optional integer advertised to Nexus for load-balancing decisions (defaults to `1`).
- `portMappings`: maps the public Nexus port to a local target using a structured form that supports hostname-specific overrides:

    ```yaml
    portMappings:
      443:
        default: "localhost:8443"
        hosts:
          api.example.com: "localhost:9443"
          "*.preview.example.com": "localhost:10443"
    ```

 Exact hostnames take precedence over wildcards, and wildcards only match a single label (e.g. `a.preview.example.com`).

### Attestation Command Contract

The client invokes the command specified under `attestation` for every Stage 0/1 exchange and subsequent re-authentication. The command is executed with these environment variables:

- `NEXUS_ATTESTATION_STAGE`: one of `handshake`, `attest`, or `reauth`.
- `NEXUS_SESSION_NONCE`: populated for Stage&nbsp;1 and re-auth requests (empty during the handshake stage).
- `NEXUS_BACKEND_NAME`: the backend name from the config block.
- `NEXUS_HOSTNAMES`: comma-separated list of hostnames associated with the backend.
- `NEXUS_WEIGHT`: numeric weight advertised to Nexus.

The command must print the signed JWT to stdout. Either of the following formats are accepted:

```
eyJhbGciOi...
```

or

```json
{"token":"eyJhbGciOi...","expiry":"2025-10-28T12:00:00Z"}
```

If `cacheHandshakeSeconds` is set in the config, handshake tokens are cached for that duration unless an explicit `expiry` is returned. All other stages are always fetched fresh.

#### Built-in HMAC signer

If you supply `attestation.hmacSecret` or `attestation.hmacSecretFile`, the client will skip the external command and sign JWTs locally using HS256. Optional fields such as `tokenTTLSeconds`, `reauthIntervalSeconds`, `reauthGraceSeconds`, and `maintenanceGraceCapSeconds` control the embedded claims. This is handy for environments that share a symmetric key with Nexus while they bring the TPM-based authorizer online.

### Example Usage

1.  Create your `config.yaml` file.
2.  Run the client:
    ```bash
    go run ./cmd/client -config config.yaml
    ```

## Library Mode

Embedding the client inside another Go service is as simple as constructing a
`client.ClientBackendConfig` and passing optional behaviour overrides. The most
useful hook is `client.WithConnectHandler`, which lets you choose the local
destination for each inbound request (or even serve it with an in-memory
`net.Conn`). `ConnectRequest` now includes an `IsTLS` flag that mirrors the
proxy's TLS detection, so your handler can apply different routing or wrap the
dial in TLS when the original client negotiated HTTPS. Returning
`client.ErrNoRoute` falls back to the static `portMappings` declared in the
config.

```go
router := func(ctx context.Context, req client.ConnectRequest) (net.Conn, error) {
    if strings.HasSuffix(req.Hostname, ".pclo.example.com") {
        return net.Dial("tcp", "localhost:5080")
    }
    // Defer to the default YAML-configured mapping.
    return nil, client.ErrNoRoute
}

c, err := client.New(cfg, client.WithConnectHandler(router))
if err != nil {
    log.Fatalf("failed to construct Nexus client: %v", err)
}
go c.Start(ctx)
```

This makes it straightforward to implement per-tenant routing rules, connect to
ephemeral processes, or hand back a `net.Pipe()` for fully in-memory handlers.
