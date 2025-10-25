package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func newWebsocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()

	serverConnCh := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("failed to upgrade: %v", err)
		}
		serverConnCh <- conn
	}))

	t.Cleanup(func() {
		srv.Close()
	})

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial test websocket: %v", err)
	}

	serverConn := <-serverConnCh

	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	return clientConn, serverConn
}

func newTestClient(t *testing.T) *Client {
	t.Helper()

	cfg := ClientBackendConfig{
		Name:         "test-backend",
		Hostnames:    []string{"example.com"},
		NexusAddress: "ws://example.com",
		AuthToken:    "token",
		PortMappings: map[int]PortMapping{
			80: {Default: "127.0.0.1:80"},
		},
	}
	c := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	c.cancel = cancel
	t.Cleanup(cancel)

	return c
}

func TestReadPumpStopsHelperGoroutineOnCancel(t *testing.T) {
	c := newTestClient(t)

	clientConn, _ := newWebsocketPair(t)
	c.wsMu.Lock()
	c.ws = clientConn
	c.wsMu.Unlock()

	done := make(chan struct{})
	c.wg.Add(1)
	go func() {
		c.readPump()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // Allow goroutines to start.

	c.cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readPump did not exit after cancellation")
	}

	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	stackDump := string(buf[:n])
	if strings.Contains(stackDump, "client.(*Client).readPump.func2") {
		t.Fatalf("readPump helper goroutine leaked\n%s", stackDump)
	}
}

func TestWritePumpDoesNotReplayStaleMessages(t *testing.T) {
	c := newTestClient(t)

	clientConn1, serverConn1 := newWebsocketPair(t)

	c.wsMu.Lock()
	c.ws = clientConn1
	c.wsMu.Unlock()

	sessionCh1 := c.beginSession()
	done1 := make(chan struct{})
	c.wg.Add(1)
	go func() {
		c.writePump(sessionCh1)
		close(done1)
	}()

	time.Sleep(20 * time.Millisecond)

	serverConn1.Close()
	clientConn1.Close()
	c.send <- []byte("trigger")

	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first writePump did not exit")
	}

	staleID := uuid.New()
	if err := c.sendControlMessage("disconnect", staleID); err == nil {
		t.Fatalf("expected error when queueing control message on inactive session")
	}

	localClient, localServer := net.Pipe()
	defer localServer.Close()
	cc := &clientConn{
		id:       staleID,
		conn:     localClient,
		hostname: "stale.test",
		quit:     make(chan struct{}),
	}
	c.localConns.Store(staleID, cc)
	go c.copyLocalToNexus(cc)

	time.Sleep(20 * time.Millisecond)
	if _, err := localServer.Write([]byte("payload")); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}
	localClient.Close()

	clientConn2, serverConn2 := newWebsocketPair(t)

	c.wsMu.Lock()
	c.ws = clientConn2
	c.wsMu.Unlock()

	sessionCh2 := c.beginSession()
	done2 := make(chan struct{})
	c.wg.Add(1)
	go func() {
		c.writePump(sessionCh2)
		close(done2)
	}()

	serverConn2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, msg, err := serverConn2.ReadMessage()
	if err == nil {
		t.Fatalf("unexpected stale message delivered to new session: %x", msg)
	}

	c.cancel()
	<-done2
}

func TestSendControlMessageSkipsMarshalErrors(t *testing.T) {
	c := newTestClient(t)

	originalMarshal := jsonMarshal
	defer func() {
		jsonMarshal = originalMarshal
	}()

	wantErr := "marshal failed"
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, fmt.Errorf(wantErr)
	}

	c.send = make(chan []byte, 1)

	c.connected.Store(true)
	err := c.sendControlMessage("ping_client", uuid.New())
	if err == nil {
		t.Fatalf("expected marshal error")
	}
	if !strings.Contains(err.Error(), wantErr) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected error containing %q, got %v", wantErr, err)
	}

	select {
	case msg := <-c.send:
		t.Fatalf("expected no message enqueued, got %x", msg)
	default:
	}
}
