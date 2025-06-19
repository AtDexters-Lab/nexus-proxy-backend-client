package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	clientIDLength      = 16
	controlByteData     = 0x01
	controlByteControl  = 0x02
	reconnectDelay      = 5 * time.Second
	healthCheckInterval = 5 * time.Second
)

// clientConn represents a single proxied connection to the local service.
type clientConn struct {
	id           uuid.UUID
	conn         net.Conn
	lastActivity atomic.Int64 // Unix timestamp of the last activity.
	pingSent     atomic.Bool  // True if an inactivity ping has been sent.
	quit         chan struct{}
}

// Client manages the full lifecycle for one configured backend service.
type Client struct {
	config     BackendConfig
	ws         *websocket.Conn
	wsMu       sync.Mutex
	localConns sync.Map
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// New creates a new Client instance for a specific backend configuration.
func New(cfg BackendConfig) *Client {
	return &Client{
		config: cfg,
	}
}

// Start initiates the client's connection loop.
func (c *Client) Start(ctx context.Context) {
	c.ctx, c.cancel = context.WithCancel(ctx)
	defer c.cleanup()

	log.Printf("INFO: [%s] Manager started for hostname: %s", c.config.Name, c.config.Hostname)

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

		c.wg.Add(2)
		go c.readPump()
		go c.healthCheckPump()

		c.wg.Wait() // Wait for pumps to exit, indicating a disconnection.
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

func (c *Client) connectAndAuthenticate() error {
	c.wsMu.Lock()
	defer c.wsMu.Unlock()

	ws, _, err := websocket.DefaultDialer.DialContext(c.ctx, c.config.NexusAddress, nil)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	c.ws = ws

	if err := c.ws.WriteMessage(websocket.TextMessage, []byte(c.config.AuthToken)); err != nil {
		c.ws.Close()
		return fmt.Errorf("auth failed: %w", err)
	}
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

	for {
		// Create a channel to receive the message from a goroutine
		msgChan := make(chan []byte)
		errChan := make(chan error)

		go func() {
			if ws == nil {
				errChan <- fmt.Errorf("connection is nil")
				return
			}
			msgType, msg, err := ws.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if msgType != websocket.BinaryMessage || len(msg) < 1 {
				errChan <- fmt.Errorf("[%s] Received non-binary message or too short payload: %d bytes", c.config.Name, len(msg))
				return
			}

			msgChan <- msg
		}()

		select {
		case <-c.ctx.Done():
			// Context was canceled, time to shut down.
			log.Println("readLoop: context done, closing connection.")
			return // Exit the loop

		case err := <-errChan:
			// An error occurred during ReadMessage.
			select {
			case <-c.ctx.Done():
				return
			default:
				log.Printf("ERROR: [%s] Error reading from Nexus: %v", c.config.Name, err)
			}
			return // Exit the loop

		case msg := <-msgChan:
			// We received a message. Process it.
			controlByte := msg[0]
			payload := msg[1:]

			switch controlByte {
			case controlByteControl:
				c.handleControlMessage(payload)
			case controlByteData:
				c.handleDataMessage(payload)
			default:
				log.Printf("ERROR: [%s] Received unknown control byte: %d", c.config.Name, controlByte)
			}
		}
	}
}

func (c *Client) handleControlMessage(payload []byte) {
	var msg struct {
		Event    string    `json:"event"`
		ClientID uuid.UUID `json:"client_id"`
		ConnPort int       `json:"conn_port"` // Port on which the client is connecting
		ClientIP string    `json:"client_ip"` // Optional field for future use
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("WARN: [%s] Failed to unmarshal control message: %v", c.config.Name, err)
		return
	}

	switch msg.Event {
	case "connect":
		localAddr, ok := c.config.PortMappings[msg.ConnPort]
		if !ok {
			log.Printf("ERROR: [%s] Received connect for unmapped destination port %d. Ignoring.", c.config.Name, msg.ConnPort)
			return
		}

		log.Printf("INFO: [%s] Received 'connect' for ClientID %s on port %d. Dialing local service at %s", c.config.Name, msg.ClientID, msg.ConnPort, localAddr)

		conn, err := net.Dial("tcp", localAddr)
		if err != nil {
			log.Printf("ERROR: [%s] Failed to connect to local service at %s: %v", c.config.Name, localAddr, err)
			return
		}

		newClient := &clientConn{
			id:   msg.ClientID,
			conn: conn,
			quit: make(chan struct{}),
		}
		newClient.lastActivity.Store(time.Now().Unix())
		c.localConns.Store(msg.ClientID, newClient)

		go c.copyToNexus(newClient)

	case "disconnect":
		log.Printf("INFO: [%s] Received 'disconnect' for ClientID: %s. Closing local connection.", c.config.Name, msg.ClientID)
		if val, ok := c.localConns.Load(msg.ClientID); ok {
			if conn, ok := val.(*clientConn); ok {
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
				log.Printf("ERROR: [%s] Failed to write data to local connection for ClientID %s: %v", c.config.Name, clientID, err)
			}
		}
	} else {
		log.Printf("WARN: [%s] No local connection found for ClientID %s. Data will be dropped.", c.config.Name, clientID)
	}
}

func (c *Client) copyToNexus(client *clientConn) {
	defer func() {
		client.conn.Close()
		c.localConns.Delete(client.id)
		log.Printf("INFO: [%s] Cleaned up local connection for ClientID %s", c.config.Name, client.id)

		c.sendControlMessage("disconnect", client.id)
	}()

	buf := make([]byte, 8192)
	for {
		select {
		case <-client.quit:
			return
		default:
			n, err := client.conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("WARN: [%s] Error reading from local connection for ClientID %s: %v", c.config.Name, client.id, err)
				}
				return
			}
			client.lastActivity.Store(time.Now().Unix()) // Reset activity timer

			header := make([]byte, 1+clientIDLength)
			header[0] = controlByteData
			copy(header[1:], client.id[:])
			message := append(header, buf[:n]...)

			c.wsMu.Lock()
			err = c.ws.WriteMessage(websocket.BinaryMessage, message)
			c.wsMu.Unlock()
			if err != nil {
				log.Printf("ERROR: [%s] Failed to write to Nexus WebSocket: %v", c.config.Name, err)
				return
			}
		}
	}
}

func (c *Client) healthCheckPump() {
	defer c.wg.Done()
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
					log.Printf("DEBUG: [%s] Client %s is idle, sending ping.", c.config.Name, conn.id)
					conn.pingSent.Store(true)
					c.sendControlMessage("ping_client", conn.id)

					// Start a timer to check for the pong.
					time.AfterFunc(pongTimeout, func() {
						if conn.pingSent.Load() {
							// Pong was not received in time.
							log.Printf("WARN: [%s] Did not receive pong for idle client %s within %s. Closing connection.", c.config.Name, conn.id, pongTimeout)
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

func (c *Client) sendControlMessage(event string, clientID uuid.UUID) {
	var msg struct {
		Event    string    `json:"event"`
		ClientID uuid.UUID `json:"client_id"`
	}
	msg.Event = event
	msg.ClientID = clientID

	payload, _ := json.Marshal(msg)
	header := []byte{controlByteControl}
	message := append(header, payload...)

	c.wsMu.Lock()
	defer c.wsMu.Unlock()
	if c.ws == nil {
		return
	}

	if err := c.ws.WriteMessage(websocket.BinaryMessage, message); err != nil {
		log.Printf("WARN: [%s] Failed to send control message '%s' for ClientID %s: %v", c.config.Name, event, clientID, err)
	}
}
