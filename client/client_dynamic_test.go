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
	}{
		Event:    "connect",
		ClientID: uuid.New(),
		ConnPort: 80,
		ClientIP: "203.0.113.10",
		Hostname: "Hello.EXAMPLE.com",
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
