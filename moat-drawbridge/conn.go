package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 70 * time.Second
	pingPeriod     = 60 * time.Second
	maxMessageSize = 65536
	sendBufSize    = 64
)

// Client represents a single WebSocket connection.
type Client struct {
	relay  *Relay
	conn   *websocket.Conn
	tags   map[string]bool // watched tags
	send   chan []byte     // outbound message queue
	authed bool
	log    *slog.Logger

	// relayURL is the public-facing relay URL used for challenge verification,
	// derived per-connection from request headers or relay config.
	relayURL string

	// deviceID is set when the client sends register_push; used by the relay to
	// track which devices are currently connected for FCM suppression.
	deviceID string

	// Pre-auth handshake fields — zeroed after authentication completes.
	nonce         string // challenge nonce, set when challenge is requested
	challengeSent bool   // true after challenge has been sent
}

// NewClient creates a new Client.
func NewClient(relay *Relay, conn *websocket.Conn, relayURL string) *Client {
	return &Client{
		relay:    relay,
		conn:     conn,
		tags:     make(map[string]bool),
		send:     make(chan []byte, sendBufSize),
		log:      relay.log,
		relayURL: relayURL,
	}
}

func generateNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate nonce: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (c *Client) sendMsg(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		c.log.Error("failed to marshal message", "error", err)
		return
	}
	select {
	case c.send <- data:
	default:
		// Send buffer full, drop message
		c.log.Warn("send buffer full, dropping message")
	}
}

func (c *Client) readPump() {
	defer func() {
		c.relay.unregister(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				c.log.Info("connection closed unexpectedly", "error", err)
			}
			return
		}

		msgType, msg, err := parseMessage(data)
		if err != nil {
			c.sendMsg(ErrorMsg{Type: "error", Message: "invalid message"})
			continue
		}

		if !c.authed {
			c.handlePreAuth(msgType, msg)
		} else {
			c.handlePostAuth(msgType, msg)
		}
	}
}

func (c *Client) handlePreAuth(msgType string, msg any) {
	switch msgType {
	case "request_challenge":
		// Generate and send challenge for DID authentication
		c.nonce = generateNonce()
		c.challengeSent = true
		c.sendMsg(ChallengeMsg{Type: "challenge", Nonce: c.nonce})

	case "challenge_response":
		if !c.challengeSent {
			c.sendMsg(ErrorMsg{Type: "error", Message: "must request challenge first"})
			return
		}

		resp, ok := msg.(*ChallengeResponseMsg)
		if !ok {
			c.sendMsg(ErrorMsg{Type: "error", Message: "invalid challenge_response"})
			return
		}

		if err := c.relay.authenticate(c, resp); err != nil {
			c.log.Info("authentication failed", "did", resp.DID, "error", err)
			c.sendMsg(ErrorMsg{Type: "error", Message: err.Error()})
			return
		}

		c.authed = true
		// Zero pre-auth state — no longer needed.
		c.nonce = ""
		c.challengeSent = false
		c.sendMsg(AuthenticatedMsg{Type: "authenticated"})
		c.log.Info("authenticated")
		// Disconnect buffer flush now happens in handleWatchTags when the
		// client re-registers its tags, keyed by tag rather than by DID.

	default:
		c.sendMsg(ErrorMsg{Type: "error", Message: "must authenticate with request_challenge"})
	}
}

func (c *Client) handlePostAuth(msgType string, msg any) {
	switch msgType {
	case "watch_tags":
		if m, ok := msg.(*WatchTagsMsg); ok {
			c.relay.handleWatchTags(c, m)
		}

	case "update_tags":
		if m, ok := msg.(*UpdateTagsMsg); ok {
			c.relay.handleUpdateTags(c, m)
		}

	case "register_push":
		if m, ok := msg.(*RegisterPushMsg); ok {
			expiry := int64(30 * 24 * 3600)
			if m.ExpirySec > 0 {
				expiry = m.ExpirySec
			}
			tags := make(map[string]bool, len(m.Tags))
			for _, t := range m.Tags {
				tags[t] = true
			}
			reg := &PushRegistration{
				DeviceID:  m.DeviceID,
				Platform:  m.Platform,
				Token:     m.Token,
				Tags:      tags,
				ExpiresAt: time.Now().Add(time.Duration(expiry) * time.Second),
			}
			c.relay.registerPush(reg)
			// Associate this device_id with the live connection so the relay can
			// suppress FCM notifications while the socket is open.
			c.relay.setClientDeviceID(c, m.DeviceID)
			c.log.Info("push token registered", "platform", m.Platform, "device_id", m.DeviceID)
		}

	case "unregister_push":
		if m, ok := msg.(*UnregisterPushMsg); ok {
			c.relay.unregisterPush(m.DeviceID)
			c.log.Info("push token unregistered", "device_id", m.DeviceID)
		}

	case "event_posted":
		if m, ok := msg.(*EventPostedMsg); ok {
			c.relay.handleEventPosted(c, m)
		}

	default:
		c.sendMsg(ErrorMsg{Type: "error", Message: "unknown message type: " + msgType})
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
