package client

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
)

// ErrNoRoute is returned by connect handlers to indicate that the request
// should fall back to the default configuration-based routing.
var ErrNoRoute = errors.New("client: no route configured")

// ConnectRequest provides context about a client connection request coming from
// the Nexus proxy.
type ConnectRequest struct {
	BackendName      string
	ClientID         uuid.UUID
	Hostname         string
	OriginalHostname string
	Port             int
	ClientIP         string
	IsTLS            bool
}

// ConnectHandler is invoked whenever the proxy asks us to establish a new
// local connection. Returning ErrNoRoute will defer to the default
// port-mapping behaviour. Any other error is treated as fatal for that request.
type ConnectHandler func(ctx context.Context, req ConnectRequest) (net.Conn, error)

// Token encapsulates the authentication token value and optional expiry.
// An Expiry value of the zero time indicates that the provider does not have
// expiry information available.
type Token struct {
	Value  string
	Expiry time.Time
}

// TokenProvider retrieves the auth token that the client should present when
// connecting to the Nexus proxy.
type TokenProvider func(ctx context.Context) (Token, error)

// Option mutates a Client during construction.
type Option func(*Client)

// WithConnectHandler registers a custom connect handler. The handler is invoked
// before the default port-mapping logic. Returning ErrNoRoute (or a nil
// connection) will fall back to the default handler.
func WithConnectHandler(handler ConnectHandler) Option {
	return func(c *Client) {
		if handler == nil {
			return
		}
		base := c.connectHandler
		c.connectHandler = func(ctx context.Context, req ConnectRequest) (net.Conn, error) {
			conn, err := handler(ctx, req)
			switch {
			case errors.Is(err, ErrNoRoute):
				return base(ctx, req)
			case err != nil:
				return nil, err
			case conn == nil:
				return base(ctx, req)
			default:
				return conn, nil
			}
		}
	}
}

// WithTokenProvider installs a callback that will be invoked to fetch an auth
// token before each connection attempt. Passing nil resets the client to use
// the static token from the configuration.
func WithTokenProvider(provider TokenProvider) Option {
	return func(c *Client) {
		if provider == nil {
			c.tokenProvider = c.staticToken
			return
		}
		c.tokenProvider = provider
	}
}
