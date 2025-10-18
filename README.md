# Nexus Proxy - Reference Backend Client

This application is a reference implementation of a backend service client for the [Nexus Proxy Server](https://github.com/AtDexters-Lab/nexus-proxy-server).

It demonstrates how a local service can securely connect to the Nexus mesh and have traffic relayed to it for multiple hostnames and ports simultaneously. This project is structured as a library (`client` package) with a simple command-line wrapper (`cmd/client/main.go`), making it easy to integrate into your own applications.

## How it Works

1.  **Configuration Driven:** The client reads a `config.yaml` file to determine which services to expose.
2.  **Connects Outbound:** For each configured service, it initiates a WebSocket connection to a Nexus Proxy node.
3.  **Presents Token:** It sends a complete, pre-signed JSON Web Token (JWT) provided in the config. The client itself has no access to the JWT secret.
4.  **Listens for Commands:** It listens for simple JSON control messages from the proxy, primarily `connect` and `disconnect` commands.
5.  **Active Health Checks:** The client actively monitors its connections. If a connection is idle for too long, it sends a `ping_client` message to the Nexus Proxy to verify the connection is still alive on the proxy side. If no `pong_client` is received, the client cleans up the local connection, preventing zombies.
6.  **Host-Aware Relaying:** `portMappings` can now route by port, hostname, or single-label wildcard (e.g. `*.preview.example.com`), allowing one backend connection to front multiple virtual hosts.

## Configuration

The client is configured via a `config.yaml` file.
See [config.example.yaml](config.example.yaml).

Key fields:

- `hostnames`: list every FQDN (or `*.example.com` wildcard) this backend will serve. These must line up with the JWT claims you provision.
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

c := client.New(cfg, client.WithConnectHandler(router))
go c.Start(ctx)
```

This makes it straightforward to implement per-tenant routing rules, connect to
ephemeral processes, or hand back a `net.Pipe()` for fully in-memory handlers.
