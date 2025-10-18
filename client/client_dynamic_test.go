package client

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClientWithCustomConnectHandler(t *testing.T) {
	cfg := ClientBackendConfig{
		Name:         "dynamic",
		Hostnames:    []string{"hello.example.com"},
		NexusAddress: "wss://nexus.example.com/connect",
		AuthToken:    "token",
		PortMappings: map[int]PortMapping{
			80: {Default: "localhost:8080"},
		},
	}

	var (
		gotReq        ConnectRequest
		handlerCalled = make(chan struct{}, 1)
		appConnCh     = make(chan net.Conn, 1)
	)

	handler := func(ctx context.Context, req ConnectRequest) (net.Conn, error) {
		gotReq = req
		server, app := net.Pipe()
		appConnCh <- app
		handlerCalled <- struct{}{}
		return server, nil
	}

	c := New(cfg, WithConnectHandler(handler))
	c.ctx, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()

	msg := struct {
		Event    string    `json:"event"`
		ClientID uuid.UUID `json:"client_id"`
		ConnPort int       `json:"conn_port"`
		ClientIP string    `json:"client_ip"`
		Hostname string    `json:"hostname"`
		IsTLS    bool      `json:"is_tls"`
	}{
		Event:    "connect",
		ClientID: uuid.New(),
		ConnPort: 80,
		ClientIP: "203.0.113.10",
		Hostname: "Hello.EXAMPLE.com",
		IsTLS:    true,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal control message: %v", err)
	}

	c.handleControlMessage(payload)

	select {
	case <-handlerCalled:
	case <-time.After(time.Second):
		t.Fatal("connect handler was not invoked")
	}

	if gotReq.Hostname != "hello.example.com" {
		t.Fatalf("expected normalized hostname, got %s", gotReq.Hostname)
	}
	if gotReq.OriginalHostname != msg.Hostname {
		t.Fatalf("expected original hostname %s, got %s", msg.Hostname, gotReq.OriginalHostname)
	}
	if gotReq.Port != msg.ConnPort {
		t.Fatalf("expected port %d, got %d", msg.ConnPort, gotReq.Port)
	}
	if gotReq.ClientIP != msg.ClientIP {
		t.Fatalf("expected client IP %s, got %s", msg.ClientIP, gotReq.ClientIP)
	}
	if !gotReq.IsTLS {
		t.Fatalf("expected IsTLS to be true")
	}

	if _, ok := c.localConns.Load(msg.ClientID); !ok {
		t.Fatalf("expected client connection to be tracked")
	}

	appConn := <-appConnCh
	appConn.Close()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := c.localConns.Load(msg.ClientID); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("expected client connection cleanup after handler close")
}

func TestClientGetAuthToken_DefaultProvider(t *testing.T) {
	cfg := ClientBackendConfig{
		Name:         "default-token",
		Hostnames:    []string{"example.com"},
		NexusAddress: "wss://nexus.example.com/connect",
		AuthToken:    "  static-token  ",
		PortMappings: map[int]PortMapping{
			80: {Default: "localhost:8080"},
		},
	}

	c := New(cfg)

	token, err := c.getAuthToken(context.Background())
	if err != nil {
		t.Fatalf("expected token, got error: %v", err)
	}
	if token != "static-token" {
		t.Fatalf("expected trimmed token value, got %q", token)
	}
}

func TestClientGetAuthToken_WithTokenProvider(t *testing.T) {
	cfg := ClientBackendConfig{
		Name:         "dynamic-token",
		Hostnames:    []string{"example.com"},
		NexusAddress: "wss://nexus.example.com/connect",
		AuthToken:    "unused",
		PortMappings: map[int]PortMapping{
			80: {Default: "localhost:8080"},
		},
	}

	var callCount int
	provider := func(ctx context.Context) (Token, error) {
		callCount++
		return Token{Value: "dynamic-token-value"}, nil
	}

	c := New(cfg, WithTokenProvider(provider))

	token, err := c.getAuthToken(context.Background())
	if err != nil {
		t.Fatalf("expected token from provider, got error: %v", err)
	}
	if token != "dynamic-token-value" {
		t.Fatalf("expected token from provider, got %q", token)
	}
	if callCount != 1 {
		t.Fatalf("expected provider to be invoked once, got %d calls", callCount)
	}
}

func TestWithTokenProviderNilResetsToStatic(t *testing.T) {
	cfg := ClientBackendConfig{
		Name:         "reset-token",
		Hostnames:    []string{"example.com"},
		NexusAddress: "wss://nexus.example.com/connect",
		AuthToken:    "static-token",
		PortMappings: map[int]PortMapping{
			80: {Default: "localhost:8080"},
		},
	}

	c := New(cfg)

	initial, err := c.getAuthToken(context.Background())
	if err != nil {
		t.Fatalf("expected initial static token, got error: %v", err)
	}
	if initial != "static-token" {
		t.Fatalf("expected initial static token, got %q", initial)
	}

	var dynamicCalls int
	dynamicProvider := func(ctx context.Context) (Token, error) {
		dynamicCalls++
		return Token{Value: "dynamic"}, nil
	}

	WithTokenProvider(dynamicProvider)(c)
	dynamic, err := c.getAuthToken(context.Background())
	if err != nil {
		t.Fatalf("expected dynamic token, got error: %v", err)
	}
	if dynamic != "dynamic" {
		t.Fatalf("expected dynamic token, got %q", dynamic)
	}
	if dynamicCalls != 1 {
		t.Fatalf("expected dynamic provider to be called once, got %d", dynamicCalls)
	}

	dynamicCalls = 0
	WithTokenProvider(nil)(c)
	reset, err := c.getAuthToken(context.Background())
	if err != nil {
		t.Fatalf("expected reset static token, got error: %v", err)
	}
	if reset != "static-token" {
		t.Fatalf("expected reset static token, got %q", reset)
	}
	if dynamicCalls != 0 {
		t.Fatalf("expected dynamic provider not to be called after reset, got %d calls", dynamicCalls)
	}
}
