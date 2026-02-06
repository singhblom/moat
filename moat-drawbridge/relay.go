package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Relay is the central hub that manages client connections and notification routing.
type Relay struct {
	mu      sync.RWMutex
	clients map[*Client]bool
	byDID   map[string]map[*Client]bool
	byTag   map[string]map[*Client]bool

	bufferMu sync.Mutex
	buffers  map[string]*DisconnectBuffer

	dedupMu sync.Mutex
	dedup   map[string]time.Time

	resolver    DIDResolver
	verifier    PDSVerifier
	rateLimiter *RateLimiter

	relayURL  string
	startTime time.Time
	log       *slog.Logger
}

// DisconnectBuffer holds notifications for a recently-disconnected client.
type DisconnectBuffer struct {
	did       string
	messages  []NewEventMsg
	expiresAt time.Time
}

// NewRelay creates a new Relay instance.
func NewRelay(relayURL string, resolver DIDResolver, verifier PDSVerifier, log *slog.Logger) *Relay {
	return &Relay{
		clients:     make(map[*Client]bool),
		byDID:       make(map[string]map[*Client]bool),
		byTag:       make(map[string]map[*Client]bool),
		buffers:     make(map[string]*DisconnectBuffer),
		dedup:       make(map[string]time.Time),
		resolver:    resolver,
		verifier:    verifier,
		rateLimiter: NewRateLimiter(),
		relayURL:    relayURL,
		startTime:   time.Now(),
		log:         log,
	}
}

// Handler returns an http.Handler with the relay's endpoints.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", r.serveWS)
	mux.HandleFunc("/health", r.healthHandler)
	return mux
}

// Run starts the relay's background goroutines. Call cancel to stop them.
func (r *Relay) Run(ctx context.Context) {
	go r.cleanupLoop(ctx)
}

func (r *Relay) serveWS(w http.ResponseWriter, req *http.Request) {
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		r.log.Error("websocket upgrade failed", "error", err)
		return
	}

	client := NewClient(r, conn)
	r.register(client)

	go client.writePump()
	go client.readPump()
}

func (r *Relay) register(c *Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[c] = true
}

func (r *Relay) unregister(c *Client) {
	r.mu.Lock()

	if _, ok := r.clients[c]; !ok {
		r.mu.Unlock()
		return
	}
	delete(r.clients, c)

	// Remove from tag index
	for tag := range c.tags {
		if clients, ok := r.byTag[tag]; ok {
			delete(clients, c)
			if len(clients) == 0 {
				delete(r.byTag, tag)
			}
		}
	}

	// Remove from DID index
	did := c.did
	if did != "" {
		if clients, ok := r.byDID[did]; ok {
			delete(clients, c)
			if len(clients) == 0 {
				delete(r.byDID, did)
			}
		}
	}

	r.mu.Unlock()

	// Create disconnect buffer if client was authenticated
	if did != "" {
		r.bufferMu.Lock()
		// Only create buffer if no other connections exist for this DID
		r.mu.RLock()
		hasOtherConns := len(r.byDID[did]) > 0
		r.mu.RUnlock()
		if !hasOtherConns {
			r.buffers[did] = &DisconnectBuffer{
				did:       did,
				expiresAt: time.Now().Add(30 * time.Second),
			}
			r.log.Info("created disconnect buffer", "did", did)
		}
		r.bufferMu.Unlock()
	}

	close(c.send)
}

func (r *Relay) registerDID(c *Client, did string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	c.did = did
	if r.byDID[did] == nil {
		r.byDID[did] = make(map[*Client]bool)
	}
	r.byDID[did][c] = true
}

func (r *Relay) handleWatchTags(c *Client, msg *WatchTagsMsg) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove old tags
	for tag := range c.tags {
		if clients, ok := r.byTag[tag]; ok {
			delete(clients, c)
			if len(clients) == 0 {
				delete(r.byTag, tag)
			}
		}
	}

	// Set new tags
	c.tags = make(map[string]bool, len(msg.Tags))
	for _, tag := range msg.Tags {
		c.tags[tag] = true
		if r.byTag[tag] == nil {
			r.byTag[tag] = make(map[*Client]bool)
		}
		r.byTag[tag][c] = true
	}

	r.log.Info("tags registered", "did", c.did, "count", len(msg.Tags))
}

func (r *Relay) handleUpdateTags(c *Client, msg *UpdateTagsMsg) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, tag := range msg.Remove {
		delete(c.tags, tag)
		if clients, ok := r.byTag[tag]; ok {
			delete(clients, c)
			if len(clients) == 0 {
				delete(r.byTag, tag)
			}
		}
	}

	for _, tag := range msg.Add {
		c.tags[tag] = true
		if r.byTag[tag] == nil {
			r.byTag[tag] = make(map[*Client]bool)
		}
		r.byTag[tag][c] = true
	}

	r.log.Info("tags updated", "did", c.did, "added", len(msg.Add), "removed", len(msg.Remove))
}

func (r *Relay) handleEventPosted(c *Client, msg *EventPostedMsg) {
	// Check rate limit
	if r.rateLimiter.IsLimited(c.did) {
		r.log.Warn("rate limited event_posted", "did", c.did, "tag", msg.Tag)
		return
	}

	// Dedup check
	dedupKey := msg.Tag + ":" + msg.RKey
	r.dedupMu.Lock()
	if last, ok := r.dedup[dedupKey]; ok && time.Since(last) < 5*time.Second {
		r.dedupMu.Unlock()
		return
	}
	r.dedup[dedupKey] = time.Now()
	r.dedupMu.Unlock()

	notification := NewEventMsg{
		Type: "new_event",
		Tag:  msg.Tag,
		RKey: msg.RKey,
		DID:  c.did,
	}

	// Collect recipients
	r.mu.RLock()
	tagClients := r.byTag[msg.Tag]
	var recipients []*Client
	for client := range tagClients {
		// Send to everyone watching this tag except the originating connection
		if client != c {
			recipients = append(recipients, client)
		}
	}
	r.mu.RUnlock()

	// Send to connected recipients
	for _, client := range recipients {
		client.sendMsg(notification)
	}

	// Buffer for disconnected DIDs
	r.bufferNotification(msg.Tag, notification)

	r.log.Info("event routed", "did", c.did, "tag", msg.Tag, "rkey", msg.RKey, "recipients", len(recipients))

	// Async PDS verification
	if r.verifier != nil {
		go r.asyncVerify(c.did, msg.RKey, msg.Tag)
	}
}

func (r *Relay) bufferNotification(tag string, notification NewEventMsg) {
	r.bufferMu.Lock()
	defer r.bufferMu.Unlock()

	for did, buf := range r.buffers {
		// We don't have the buffered client's tags anymore, so we buffer all notifications.
		// This is slightly over-broad but simple. The client will ignore irrelevant ones.
		_ = did
		buf.messages = append(buf.messages, notification)
	}
}

func (r *Relay) flushBuffer(c *Client) {
	r.bufferMu.Lock()
	buf, ok := r.buffers[c.did]
	if ok {
		delete(r.buffers, c.did)
	}
	r.bufferMu.Unlock()

	if !ok || len(buf.messages) == 0 {
		return
	}

	r.log.Info("flushing disconnect buffer", "did", c.did, "count", len(buf.messages))
	for _, msg := range buf.messages {
		c.sendMsg(msg)
	}
}

func (r *Relay) asyncVerify(did, rkey, tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := r.verifier.Verify(ctx, did, rkey, tag); err != nil {
		r.log.Warn("PDS verification failed", "did", did, "rkey", rkey, "error", err)
		r.rateLimiter.RecordFailure(did)
	}
}

func (r *Relay) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.cleanupDedup()
			r.cleanupBuffers()
		}
	}
}

func (r *Relay) cleanupDedup() {
	r.dedupMu.Lock()
	defer r.dedupMu.Unlock()

	now := time.Now()
	for key, t := range r.dedup {
		if now.Sub(t) > 5*time.Second {
			delete(r.dedup, key)
		}
	}
}

func (r *Relay) cleanupBuffers() {
	r.bufferMu.Lock()
	defer r.bufferMu.Unlock()

	now := time.Now()
	for did, buf := range r.buffers {
		if now.After(buf.expiresAt) {
			r.log.Info("disconnect buffer expired", "did", did)
			delete(r.buffers, did)
		}
	}
}

func (r *Relay) healthHandler(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	connCount := len(r.clients)
	tagCount := len(r.byTag)
	r.mu.RUnlock()

	resp := map[string]any{
		"status":         "ok",
		"uptime_seconds": int(time.Since(r.startTime).Seconds()),
		"connections":    connCount,
		"tags_tracked":   tagCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
