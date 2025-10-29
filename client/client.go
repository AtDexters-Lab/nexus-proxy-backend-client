package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var jsonMarshal = json.Marshal

const (
	clientIDLength      = 16
	controlByteData     = 0x01
	controlByteControl  = 0x02
	reconnectDelay      = 5 * time.Second
	healthCheckInterval = 5 * time.Second

	writeToNexusBufferSize = 1024 * 16 // The server specifies a maximum read size of 32KB + 17 bytes for the header, so 16KB is a safe size.
	// connection health check parameters
	writeWait        = 10 * time.Second
	pingInterval     = 5 * time.Second
	pongWait         = 10 * time.Second
	handshakeTimeout = 15 * time.Second
	maxMessageSize   = 32*1024 + 17
)

var errSessionInactive = errors.New("client session inactive")

type outboundMessage struct {
	messageType int
	payload     []byte
}

type challengeMessage struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
}

// clientConn represents a single proxied connection to the local service.
type clientConn struct {
	id           uuid.UUID
	conn         net.Conn
	hostname     string
	lastActivity atomic.Int64 // Unix timestamp of the last activity.
	pingSent     atomic.Bool  // True if an inactivity ping has been sent.
	quit         chan struct{}
}

type ClientBackendConfig struct {
	Name         string
	Hostnames    []string
	NexusAddress string
	Weight       int
	Attestation  AttestationOptions
	PortMappings map[int]PortMapping
	HealthChecks HealthCheckConfig
}

// Client manages the full lifecycle for one configured backend service.
type Client struct {
	config              ClientBackendConfig
	ws                  *websocket.Conn
	wsMu                sync.Mutex
	localConns          sync.Map
	send                chan outboundMessage
	connected           atomic.Bool
	sessionDone         atomic.Value // stores chan struct{}
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	connectHandler      ConnectHandler
	tokenProvider       TokenProvider
	staticTokenProvider TokenProvider
}

// New creates a new Client instance for a specific backend configuration.
func New(cfg ClientBackendConfig, opts ...Option) (*Client, error) {
	if cfg.Weight <= 0 {
		cfg.Weight = 1
	}

	defaultProvider, err := buildDefaultProvider(cfg)
	if err != nil {
		return nil, err
	}

	c := &Client{
		config: cfg,
		send:   make(chan outboundMessage, 256), // Buffered channel to handle outgoing messages
	}
	c.sessionDone.Store((chan struct{})(nil))

	c.connectHandler = c.configBasedConnectHandler()
	c.staticTokenProvider = defaultProvider
	c.tokenProvider = defaultProvider

	for _, opt := range opts {
		opt(c)
	}
	if c.connectHandler == nil {
		c.connectHandler = c.configBasedConnectHandler()
	}
	if c.staticTokenProvider == nil && c.tokenProvider != nil {
		c.staticTokenProvider = c.tokenProvider
	}
	if c.tokenProvider == nil {
		if defaultProvider == nil {
			return nil, fmt.Errorf("token provider not configured and no attestation mechanism supplied")
		}
		c.tokenProvider = defaultProvider
	}
	if c.staticTokenProvider == nil {
		c.staticTokenProvider = defaultProvider
	}

	return c, nil
}

func buildDefaultProvider(cfg ClientBackendConfig) (TokenProvider, error) {
	opts := cfg.Attestation
	if strings.TrimSpace(opts.Command) != "" {
		return NewCommandTokenProvider(opts)
	}
	if strings.TrimSpace(opts.HMACSecret) != "" || strings.TrimSpace(opts.HMACSecretFile) != "" {
		return NewHMACTokenProvider(opts, cfg.Name, cfg.Hostnames, cfg.Weight)
	}
	return nil, nil
}

// Start initiates the client's connection loop.
func (c *Client) Start(ctx context.Context) {
	c.ctx, c.cancel = context.WithCancel(ctx)
	defer c.cleanup()

	log.Printf("INFO: [%s] Manager started for hostnames: %s", c.config.Name, strings.Join(c.config.Hostnames, ", "))

	// Start the health check pump to monitor connection health.
	go c.healthCheckPump()

	for {
		select {
		case <-c.ctx.Done():
			log.Printf("INFO: [%s] Context canceled. Manager stopping.", c.config.Name)
			return
		default:
		}

		if err := c.connectAndAuthenticate(); err != nil {
			log.Printf("WARN: [%s] Failed to connect and authenticate: %v. Retrying in %s...", c.config.Name, err, reconnectDelay)
			time.Sleep(reconnectDelay)
			continue
		}

		log.Printf("INFO: [%s] Connection established and authenticated. Starting pumps.", c.config.Name)

		sessionCh := c.beginSession()

		c.wg.Add(1)
		go c.readPump()

		c.wg.Add(1)
		go c.writePump(sessionCh)

		c.wg.Wait() // Wait for pumps to exit, indicating a disconnection.
		c.clearSendQueue()
		log.Printf("INFO: [%s] Disconnected from Nexus Proxy.", c.config.Name)
	}
}

// Stop gracefully shuts down the client and its connections.
func (c *Client) Stop() {
	log.Printf("INFO: [%s] Stopping client...", c.config.Name)
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Client) getAuthToken(ctx context.Context) (string, error) {
	return c.issueToken(ctx, StageHandshake, "")
}

func (c *Client) issueToken(ctx context.Context, stage TokenStage, nonce string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	provider := c.tokenProvider
	if provider == nil {
		return "", fmt.Errorf("token provider not configured")
	}

	req := TokenRequest{
		Stage:        stage,
		SessionNonce: nonce,
		BackendName:  c.config.Name,
		Hostnames:    append([]string(nil), c.config.Hostnames...),
		Weight:       c.config.Weight,
	}

	token, err := provider.IssueToken(ctx, req)
	if err != nil {
		return "", fmt.Errorf("token provider failed: %w", err)
	}

	value := strings.TrimSpace(token.Value)
	if value == "" {
		return "", fmt.Errorf("token provider returned empty token")
	}

	return value, nil
}

func (c *Client) connectAndAuthenticate() error {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	ws, _, err := websocket.DefaultDialer.DialContext(ctx, c.config.NexusAddress, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	handshakeToken, err := c.issueToken(ctx, StageHandshake, "")
	if err != nil {
		ws.Close()
		return fmt.Errorf("fetch handshake token: %w", err)
	}

	if err := ws.WriteMessage(websocket.TextMessage, []byte(handshakeToken)); err != nil {
		ws.Close()
		return fmt.Errorf("send handshake token: %w", err)
	}

	nonce, err := c.awaitChallenge(ws, "handshake_challenge")
	if err != nil {
		ws.Close()
		return fmt.Errorf("handshake challenge: %w", err)
	}

	attestedToken, err := c.issueToken(ctx, StageAttest, nonce)
	if err != nil {
		ws.Close()
		return fmt.Errorf("fetch attested token: %w", err)
	}

	if err := ws.WriteMessage(websocket.TextMessage, []byte(attestedToken)); err != nil {
		ws.Close()
		return fmt.Errorf("send attested token: %w", err)
	}

	c.wsMu.Lock()
	c.ws = ws
	c.wsMu.Unlock()

	return nil
}

func (c *Client) cleanup() {
	c.localConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*clientConn); ok {
			conn.conn.Close()
		}
		return true
	})
	log.Printf("INFO: [%s] Client cleanup complete.", c.config.Name)
}

func (c *Client) readPump() {
	defer c.wg.Done()
	c.wsMu.Lock()
	ws := c.ws
	c.wsMu.Unlock()
	defer ws.Close()

	ws.SetReadLimit(maxMessageSize)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		msgType, message, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("ERROR: [%s] Unexpected close from Nexus: %v", c.config.Name, err)
			}
			return
		}

		ws.SetReadDeadline(time.Now().Add(pongWait))

		switch msgType {
		case websocket.BinaryMessage:
			c.handleBinaryMessage(message)
		case websocket.TextMessage:
			if err := c.handleTextMessage(message); err != nil {
				log.Printf("ERROR: [%s] Re-authentication failed: %v", c.config.Name, err)
				return
			}
		case websocket.CloseMessage:
			return
		default:
			log.Printf("WARN: [%s] Ignoring unsupported WebSocket message type %d", c.config.Name, msgType)
		}
	}
}

func (c *Client) handleControlMessage(payload []byte) {
	var msg struct {
		Event    string    `json:"event"`
		ClientID uuid.UUID `json:"client_id"`
		ConnPort int       `json:"conn_port"` // Port on which the client is connecting
		ClientIP string    `json:"client_ip"` // Optional field for future use
		Hostname string    `json:"hostname"`
		IsTLS    bool      `json:"is_tls"` // Indicates whether the original client spoke TLS.
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("WARN: [%s] Failed to unmarshal control message: %v", c.config.Name, err)
		return
	}

	switch msg.Event {
	case "connect":
		normalizedHost := normalizeHostname(msg.Hostname)
		if normalizedHost == "" {
			normalizedHost = msg.Hostname
		}
		log.Printf("INFO: [%s] Received 'connect' for ClientID %s on port %d (hostname: %s, tls:%v).", c.config.Name, msg.ClientID, msg.ConnPort, normalizedHost, msg.IsTLS)

		req := ConnectRequest{
			BackendName:      c.config.Name,
			ClientID:         msg.ClientID,
			Hostname:         normalizedHost,
			OriginalHostname: msg.Hostname,
			Port:             msg.ConnPort,
			ClientIP:         msg.ClientIP,
			IsTLS:            msg.IsTLS,
		}

		conn, err := c.openBackendConnection(req)
		if err != nil {
			if errors.Is(err, ErrNoRoute) {
				log.Printf("ERROR: [%s] No route configured for hostname '%s' on port %d", c.config.Name, msg.Hostname, msg.ConnPort)
			} else {
				log.Printf("ERROR: [%s] Failed to establish local connection for client %s: %v", c.config.Name, msg.ClientID, err)
			}
			return
		}

		newClient := &clientConn{
			id:       msg.ClientID,
			conn:     conn,
			hostname: normalizedHost,
			quit:     make(chan struct{}),
		}
		newClient.lastActivity.Store(time.Now().Unix())
		c.localConns.Store(msg.ClientID, newClient)

		go c.copyLocalToNexus(newClient)

	case "disconnect":
		log.Printf("INFO: [%s] Received 'disconnect' for ClientID: %s. Closing local connection.", c.config.Name, msg.ClientID)
		if val, ok := c.localConns.Load(msg.ClientID); ok {
			if conn, ok := val.(*clientConn); ok {
				if conn.hostname != "" {
					log.Printf("DEBUG: [%s] Disconnecting client %s for hostname %s", c.config.Name, msg.ClientID, conn.hostname)
				}
				close(conn.quit)
				conn.conn.Close()
				c.localConns.Delete(msg.ClientID)
			}
		}

	case "pong_client":
		log.Printf("DEBUG: [%s] Received pong for client %s", c.config.Name, msg.ClientID)
		if val, ok := c.localConns.Load(msg.ClientID); ok {
			if conn, ok := val.(*clientConn); ok {
				conn.pingSent.Store(false)
				conn.lastActivity.Store(time.Now().Unix())
			}
		}
	}
}

func (c *Client) resolveLocalAddress(port int, hostname string) (string, bool) {
	mapping, ok := c.config.PortMappings[port]
	if !ok {
		return "", false
	}
	return mapping.Resolve(hostname)
}

func (c *Client) openBackendConnection(req ConnectRequest) (net.Conn, error) {
	handler := c.connectHandler
	if handler == nil {
		return nil, fmt.Errorf("connect handler not configured")
	}

	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	conn, err := handler(ctx, req)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, fmt.Errorf("connect handler returned nil connection without error")
	}
	return conn, nil
}

func (c *Client) configBasedConnectHandler() ConnectHandler {
	return func(ctx context.Context, req ConnectRequest) (net.Conn, error) {
		localAddr, ok := c.resolveLocalAddress(req.Port, req.Hostname)
		if !ok {
			return nil, ErrNoRoute
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", localAddr)
	}
}

func (c *Client) handleDataMessage(payload []byte) {
	if len(payload) < clientIDLength {
		return
	}

	var clientID uuid.UUID
	copy(clientID[:], payload[:clientIDLength])
	data := payload[clientIDLength:]

	val, ok := c.localConns.Load(clientID)
	if ok {
		if conn, ok := val.(*clientConn); ok {
			conn.lastActivity.Store(time.Now().Unix()) // Reset activity timer
			_, err := conn.conn.Write(data)
			if err != nil {
				conn.conn.Close()
				if conn.hostname != "" {
					log.Printf("ERROR: [%s] Failed to write data to local connection for ClientID %s (%s): %v", c.config.Name, clientID, conn.hostname, err)
				} else {
					log.Printf("ERROR: [%s] Failed to write data to local connection for ClientID %s: %v", c.config.Name, clientID, err)
				}
			}
		}
	} else {
		log.Printf("WARN: [%s] No local connection found for ClientID %s. Data will be dropped. Disconnect will be sent to proxy", c.config.Name, clientID)
		if err := c.sendControlMessage("disconnect", clientID); err != nil {
			log.Printf("DEBUG: [%s] Failed to enqueue disconnect for ClientID %s: %v", c.config.Name, clientID, err)
		}
	}
}

func (c *Client) copyLocalToNexus(client *clientConn) {
	defer func() {
		client.conn.Close()
		c.localConns.Delete(client.id)
		if client.hostname != "" {
			log.Printf("INFO: [%s] Cleaned up local connection for ClientID %s (%s)", c.config.Name, client.id, client.hostname)
		} else {
			log.Printf("INFO: [%s] Cleaned up local connection for ClientID %s", c.config.Name, client.id)
		}

		if err := c.sendControlMessage("disconnect", client.id); err != nil {
			log.Printf("DEBUG: [%s] Failed to enqueue disconnect for ClientID %s: %v", c.config.Name, client.id, err)
		}
	}()

	buf := make([]byte, writeToNexusBufferSize)
	for {
		select {
		case <-client.quit:
			return
		default:
			n, err := client.conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					if client.hostname != "" {
						log.Printf("WARN: [%s] Error reading from local connection for ClientID %s (%s): %v", c.config.Name, client.id, client.hostname, err)
					} else {
						log.Printf("WARN: [%s] Error reading from local connection for ClientID %s: %v", c.config.Name, client.id, err)
					}
				}
				return
			}
			client.lastActivity.Store(time.Now().Unix()) // Reset activity timer

			header := make([]byte, 1+clientIDLength)
			header[0] = controlByteData
			copy(header[1:], client.id[:])
			message := append(header, buf[:n]...)

			outbound := outboundMessage{
				messageType: websocket.BinaryMessage,
				payload:     message,
			}

			if err := c.enqueue(outbound); err != nil {
				if !errors.Is(err, errSessionInactive) && !errors.Is(err, context.Canceled) {
					log.Printf("WARN: [%s] Failed to enqueue data for ClientID %s: %v", c.config.Name, client.id, err)
				}
				return
			}
		}
	}
}

func (c *Client) clearSendQueue() {
	for {
		select {
		case <-c.send:
		default:
			return
		}
	}
}

func (c *Client) beginSession() chan struct{} {
	sessionCh := make(chan struct{})
	c.sessionDone.Store(sessionCh)
	c.connected.Store(true)
	return sessionCh
}

func (c *Client) enqueue(message outboundMessage) error {
	if !c.connected.Load() {
		return errSessionInactive
	}

	var done <-chan struct{}
	if v := c.sessionDone.Load(); v != nil {
		if ch, ok := v.(chan struct{}); ok && ch != nil {
			done = ch
		}
	}

	if c.ctx == nil {
		if done != nil {
			select {
			case c.send <- message:
				return nil
			case <-done:
				return errSessionInactive
			}
		}
		c.send <- message
		return nil
	}

	if done != nil {
		select {
		case c.send <- message:
			return nil
		case <-done:
			return errSessionInactive
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}

	select {
	case c.send <- message:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

func (c *Client) sendControlMessage(event string, clientID uuid.UUID) error {
	var msg struct {
		Event    string    `json:"event"`
		ClientID uuid.UUID `json:"client_id"`
	}
	msg.Event = event
	msg.ClientID = clientID

	payload, err := jsonMarshal(msg)
	if err != nil {
		log.Printf("ERROR: [%s] Failed to marshal control message '%s' for client %s: %v", c.config.Name, event, clientID, err)
		return err
	}
	header := []byte{controlByteControl}
	message := append(header, payload...)
	outbound := outboundMessage{
		messageType: websocket.BinaryMessage,
		payload:     message,
	}

	if err := c.enqueue(outbound); err != nil {
		if errors.Is(err, errSessionInactive) {
			log.Printf("DEBUG: [%s] Dropping control message '%s' for client %s: session inactive", c.config.Name, event, clientID)
		} else if errors.Is(err, context.Canceled) {
			log.Printf("DEBUG: [%s] Dropping control message '%s' for client %s: client context canceled", c.config.Name, event, clientID)
		} else {
			log.Printf("WARN: [%s] Failed to enqueue control message '%s' for client %s: %v", c.config.Name, event, clientID, err)
		}
		return err
	}
	return nil
}

func (c *Client) writePump(sessionCh chan struct{}) {
	defer c.wg.Done()
	c.wsMu.Lock()
	ws := c.ws
	c.wsMu.Unlock()

	if sessionCh == nil {
		sessionCh = c.beginSession()
	}

	ticker := time.NewTicker(pingInterval)
	defer func() {
		c.connected.Store(false)
		close(sessionCh)
		c.sessionDone.Store((chan struct{})(nil))
		c.clearSendQueue()
		if ws != nil {
			ws.Close()
		}
		ticker.Stop()
		log.Printf("DEBUG: [%s] Write pump stopped.", c.config.Name)
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// The send channel was closed.
				ws.SetWriteDeadline(time.Now().Add(writeWait))
				ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(message.messageType, message.payload); err != nil {
				log.Printf("ERROR: [%s] Failed to write message to Nexus: %v", c.config.Name, err)
				return // Terminate the pump and session.
			}
		case <-ticker.C:
			// Send a WebSocket-level ping to keep the connection alive.
			if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
				log.Printf("ERROR: [%s] Failed to write ping to Nexus: %v", c.config.Name, err)
				return // Terminate the pump and session.
			}
		case <-c.ctx.Done():
			// The session context was canceled.
			return
		}
	}
}

func (c *Client) healthCheckPump() {
	if !c.config.HealthChecks.Enabled {
		return
	}

	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	inactivityTimeout := time.Duration(c.config.HealthChecks.InactivityTimeout) * time.Second
	pongTimeout := time.Duration(c.config.HealthChecks.PongTimeout) * time.Second

	for {
		select {
		case <-ticker.C:
			c.localConns.Range(func(key, value interface{}) bool {
				conn, ok := value.(*clientConn)
				if !ok {
					return true
				}

				if conn.pingSent.Load() {
					// Ping was sent, but we haven't received a pong yet.
					// We let the pong timeout handle the cleanup.
					return true
				}

				if time.Since(time.Unix(conn.lastActivity.Load(), 0)) > inactivityTimeout {
					if conn.hostname != "" {
						log.Printf("DEBUG: [%s] Client %s (%s) is idle, sending ping.", c.config.Name, conn.id, conn.hostname)
					} else {
						log.Printf("DEBUG: [%s] Client %s is idle, sending ping.", c.config.Name, conn.id)
					}
					conn.pingSent.Store(true)
					if err := c.sendControlMessage("ping_client", conn.id); err != nil {
						conn.pingSent.Store(false)
						log.Printf("DEBUG: [%s] Failed to send ping for client %s: %v", c.config.Name, conn.id, err)
					}

					// Start a timer to check for the pong.
					time.AfterFunc(pongTimeout, func() {
						if conn.pingSent.Load() {
							// Pong was not received in time.
							if conn.hostname != "" {
								log.Printf("WARN: [%s] Did not receive pong for idle client %s (%s) within %s. Closing connection.", c.config.Name, conn.id, conn.hostname, pongTimeout)
							} else {
								log.Printf("WARN: [%s] Did not receive pong for idle client %s within %s. Closing connection.", c.config.Name, conn.id, pongTimeout)
							}
							conn.conn.Close() // This will trigger the full cleanup process.
						}
					})
				}
				return true
			})
		case <-c.ctx.Done():
			return
		}
	}
}
func (c *Client) awaitChallenge(ws *websocket.Conn, expectedType string) (string, error) {
	if err := ws.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return "", err
	}
	defer ws.SetReadDeadline(time.Time{})

	messageType, payload, err := ws.ReadMessage()
	if err != nil {
		return "", err
	}
	if messageType != websocket.TextMessage {
		return "", fmt.Errorf("expected text message during handshake, got type %d", messageType)
	}

	var challenge challengeMessage
	if err := json.Unmarshal(payload, &challenge); err != nil {
		return "", fmt.Errorf("decode challenge: %w", err)
	}
	if challenge.Type != expectedType {
		return "", fmt.Errorf("unexpected challenge type %q", challenge.Type)
	}
	if strings.TrimSpace(challenge.Nonce) == "" {
		return "", fmt.Errorf("challenge missing nonce")
	}
	return challenge.Nonce, nil
}
func (c *Client) handleBinaryMessage(message []byte) {
	if len(message) < 1 {
		log.Printf("WARN: [%s] Received empty binary message from Nexus", c.config.Name)
		return
	}

	controlByte := message[0]
	payload := message[1:]

	switch controlByte {
	case controlByteControl:
		c.handleControlMessage(payload)
	case controlByteData:
		c.handleDataMessage(payload)
	default:
		log.Printf("ERROR: [%s] Received unknown control byte: %d", c.config.Name, controlByte)
	}
}

func (c *Client) handleTextMessage(message []byte) error {
	var challenge challengeMessage
	if err := json.Unmarshal(message, &challenge); err != nil {
		log.Printf("WARN: [%s] Failed to decode text message from Nexus: %v", c.config.Name, err)
		return nil
	}

	switch challenge.Type {
	case "reauth_challenge":
		if strings.TrimSpace(challenge.Nonce) == "" {
			return fmt.Errorf("reauth challenge missing nonce")
		}
		return c.handleReauthChallenge(challenge.Nonce)
	case "handshake_challenge":
		// Should not occur after initial handshake; ignore quietly.
		log.Printf("WARN: [%s] Received unexpected handshake challenge after session establishment", c.config.Name)
	default:
		log.Printf("WARN: [%s] Ignoring unknown text message type '%s' from Nexus", c.config.Name, challenge.Type)
	}
	return nil
}

func (c *Client) handleReauthChallenge(nonce string) error {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	token, err := c.issueToken(ctx, StageReauth, nonce)
	if err != nil {
		return fmt.Errorf("issue reauth token: %w", err)
	}

	outbound := outboundMessage{
		messageType: websocket.TextMessage,
		payload:     []byte(token),
	}

	if err := c.enqueue(outbound); err != nil {
		return fmt.Errorf("enqueue reauth token: %w", err)
	}
	return nil
}
