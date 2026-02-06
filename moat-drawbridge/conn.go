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

// Client represents a single WebSocket connection.
type Client struct {
	relay     *Relay
	conn      *websocket.Conn
	did       string          // set after authentication
	tags      map[string]bool // watched tags
	pushToken *PushToken      // optional
	send      chan []byte     // outbound message queue
	nonce     string          // challenge nonce (set on connect, cleared after auth)
	authed    bool
	log       *slog.Logger
}

// NewClient creates a new Client and sends the initial challenge.
func NewClient(relay *Relay, conn *websocket.Conn) *Client {
	nonce := generateNonce()
	c := &Client{
		relay: relay,
		conn:  conn,
		tags:  make(map[string]bool),
		send:  make(chan []byte, sendBufSize),
		nonce: nonce,
		log:   relay.log,
	}
	return c
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

	// Send initial challenge
	c.sendMsg(ChallengeMsg{Type: "challenge", Nonce: c.nonce})

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
	if msgType != "challenge_response" {
		c.sendMsg(ErrorMsg{Type: "error", Message: "must authenticate first"})
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
	c.log = c.log.With("did", c.did)
	c.sendMsg(AuthenticatedMsg{Type: "authenticated"})
	c.log.Info("client authenticated")

	// Flush any buffered notifications
	c.relay.flushBuffer(c)
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
	case "event_posted":
		if m, ok := msg.(*EventPostedMsg); ok {
			c.relay.handleEventPosted(c, m)
		}
	case "register_push":
		if m, ok := msg.(*RegisterPushMsg); ok {
			c.relay.mu.Lock()
			c.pushToken = &PushToken{Platform: m.Platform, Token: m.Token}
			c.relay.mu.Unlock()
			c.log.Info("push token registered", "platform", m.Platform)
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
