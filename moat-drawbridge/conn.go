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

// PushToken holds a client's push notification token.
type PushToken struct {
	Platform string // "fcm" or "apns"
	Token    string
}

// AuthMode represents the client's authentication mode.
type AuthMode int

const (
	AuthModeNone      AuthMode = iota
	AuthModeSender             // DID-authenticated, can event_posted + manage tickets
	AuthModeRecipient          // Ticket-authenticated, can watch_tags + register_push
)

// Client represents a single WebSocket connection.
type Client struct {
	relay     *Relay
	conn      *websocket.Conn
	tags      map[string]bool // watched tags
	pushToken *PushToken      // optional
	send      chan []byte     // outbound message queue
	authed    bool
	authMode  AuthMode
	log       *slog.Logger

	// relayURL is the public-facing relay URL used for challenge verification,
	// derived per-connection from request headers or relay config.
	relayURL string

	// Sender-specific (AuthModeSender)
	did           string // set after DID authentication
	nonce         string // challenge nonce, set when challenge is requested
	challengeSent bool   // true after challenge has been sent

	// Recipient-specific (AuthModeRecipient)
	ticket string // set after ticket authentication
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
		c.log.Warn("send buffer full, dropping message", "did", c.did)
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
				c.log.Info("connection closed unexpectedly", "did", c.did, "error", err)
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
		c.authMode = AuthModeSender
		c.log = c.log.With("did", c.did)
		c.sendMsg(AuthenticatedMsg{Type: "authenticated"})
		c.log.Info("sender authenticated")

		// Flush any buffered notifications
		c.relay.flushBuffer(c)

	case "ticket_auth":
		resp, ok := msg.(*TicketAuthMsg)
		if !ok {
			c.sendMsg(ErrorMsg{Type: "error", Message: "invalid ticket_auth"})
			return
		}

		if err := c.relay.authenticateTicket(c, resp.Ticket); err != nil {
			c.log.Info("ticket authentication failed", "error", err)
			c.sendMsg(ErrorMsg{Type: "error", Message: err.Error()})
			return
		}

		c.authed = true
		c.authMode = AuthModeRecipient
		c.log = c.log.With("ticket_prefix", c.ticket[:16])
		c.sendMsg(TicketAuthenticatedMsg{Type: "ticket_authenticated"})
		c.log.Info("recipient authenticated")

	default:
		c.sendMsg(ErrorMsg{Type: "error", Message: "must authenticate with request_challenge or ticket_auth"})
	}
}

func (c *Client) handlePostAuth(msgType string, msg any) {
	switch msgType {
	case "watch_tags":
		// Allowed for both senders and recipients
		if m, ok := msg.(*WatchTagsMsg); ok {
			c.relay.handleWatchTags(c, m)
		}

	case "update_tags":
		// Allowed for both senders and recipients
		if m, ok := msg.(*UpdateTagsMsg); ok {
			c.relay.handleUpdateTags(c, m)
		}

	case "register_push":
		// Allowed for both senders and recipients
		if m, ok := msg.(*RegisterPushMsg); ok {
			c.relay.mu.Lock()
			c.pushToken = &PushToken{Platform: m.Platform, Token: m.Token}
			c.relay.mu.Unlock()
			c.log.Info("push token registered", "platform", m.Platform)
		}

	case "event_posted":
		// Sender-only: requires DID authentication
		if c.authMode != AuthModeSender {
			c.sendMsg(ErrorMsg{Type: "error", Message: "event_posted requires DID authentication"})
			return
		}
		if m, ok := msg.(*EventPostedMsg); ok {
			c.relay.handleEventPosted(c, m)
		}

	case "register_ticket":
		// Sender-only: requires DID authentication
		if c.authMode != AuthModeSender {
			c.sendMsg(ErrorMsg{Type: "error", Message: "register_ticket requires DID authentication"})
			return
		}
		if m, ok := msg.(*RegisterTicketMsg); ok {
			c.relay.handleRegisterTicket(c, m)
		}

	case "revoke_ticket":
		// Sender-only: requires DID authentication
		if c.authMode != AuthModeSender {
			c.sendMsg(ErrorMsg{Type: "error", Message: "revoke_ticket requires DID authentication"})
			return
		}
		if m, ok := msg.(*RevokeTicketMsg); ok {
			c.relay.handleRevokeTicket(c, m)
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
