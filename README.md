# Nexus Proxy - Reference Backend Client

This application is a reference implementation of a backend service client for the [Nexus Proxy Server](https://github.com/AtDexters-Lab/nexus-proxy-server).

It demonstrates how a local service can securely connect to the Nexus mesh and have traffic relayed to it for multiple hostnames and ports simultaneously. This project is structured as a library (`client` package) with a simple command-line wrapper (`cmd/client/main.go`), making it easy to integrate into your own applications.

## How it Works

1.  **Configuration Driven:** The client reads a `config.yaml` file to determine which services to expose.
2.  **Connects Outbound:** For each configured service, it initiates a WebSocket connection to a Nexus Proxy node.
3.  **Presents Token:** It sends a complete, pre-signed JSON Web Token (JWT) provided in the config. The client itself has no access to the JWT secret.
4.  **Listens for Commands:** It listens for simple JSON control messages from the proxy, primarily `connect` and `disconnect` commands.
5.  **Active Health Checks:** The client actively monitors its connections. If a connection is idle for too long, it sends a `ping_client` message to the Nexus Proxy to verify the connection is still alive on the proxy side. If no `pong_client` is received, the client cleans up the local connection, preventing zombies.
6.  **Multi-Port Relaying:** Based on port mappings in the config, it relays traffic between the Nexus proxy and the appropriate local service.

## Configuration

The client is configured via a `config.yaml` file.

```yaml
# config.yaml

# A list of backend services this client will manage.
# This allows one client process to handle multiple distinct services.
backends:
  -
    # A friendly name for this configuration block.
    name: "webapp"
    # The public-facing hostname this backend is responsible for.
    hostname: "app.example.com"
    # The WebSocket address of the Nexus Proxy server.
    nexusAddress: "wss://nexus.example.com/connect"
    # The full, pre-signed JWT obtained from a central authorizer.
    authToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    # A map of public-facing relay ports on Nexus to local service ports.
    portMappings:
      443: "localhost:8443"  # Relay HTTPS traffic to a local web server
      80: "localhost:8080"   # Relay HTTP traffic
    # Configuration for active client health checks.
    healthChecks:
      # Enable active health checks. Recommended.
      enabled: true
      # Time in seconds a connection can be idle before a ping is sent.
      inactivityTimeout: 60
      # Time in seconds to wait for a pong from the proxy after a ping is sent.
      pongTimeout: 5
  -
    name: "email-server"
    hostname: "imap.example.com"
    nexusAddress: "wss://nexus.example.com/connect"
    authToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    portMappings:
      993: "localhost:993"  # Relay secure IMAP (IMAPS) traffic
```

### Example Usage

1.  Create your `config.yaml` file.
2.  Run the client:
    ```bash
    go run ./cmd/client -config config.yaml
    ```