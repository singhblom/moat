package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// propEnv is a minimal test environment for property tests.
type propEnv struct {
	relay *Relay
}

func newPropEnv() *propEnv {
	log := slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	relay := NewRelay("", "ws://test", nil, nil, log)
	ctx, cancel := context.WithCancel(context.Background())
	relay.Run(ctx)
	go func() {
		<-ctx.Done()
	}()
	_ = cancel // keep for cleanup if needed
	return &propEnv{relay: relay}
}

func randomDID(rng *rand.Rand) string {
	b := make([]byte, 8)
	rng.Read(b)
	return "did:plc:" + hex.EncodeToString(b)
}

func randomTag(rng *rand.Rand) string {
	b := make([]byte, 16)
	rng.Read(b)
	return hex.EncodeToString(b)
}

func randomPayload(rng *rand.Rand) string {
	size := rng.Intn(4096) + 1
	b := make([]byte, size)
	rng.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Property: byTag map consistency with client.tags
func TestProp_ByTagConsistency(t *testing.T) {
	rng := rand.New(rand.NewSource(45))

	for i := 0; i < 50; i++ {
		env := newPropEnv()

		// Create several clients with random tags
		numClients := rng.Intn(10) + 1
		clients := make([]*Client, numClients)

		for j := 0; j < numClients; j++ {
			c := &Client{
				relay: env.relay,
				tags:  make(map[string]bool),
				send:  make(chan []byte, 10),
			}
			clients[j] = c
			env.relay.register(c)

			// Watch random tags
			numTags := rng.Intn(5)
			tags := make([]string, numTags)
			for k := 0; k < numTags; k++ {
				tags[k] = randomTag(rng)
			}
			env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: tags})
		}

		// Verify consistency: for each client, their tags should match byTag entries
		env.relay.mu.RLock()
		for _, c := range clients {
			for tag := range c.tags {
				if tagClients, ok := env.relay.byTag[tag]; !ok || !tagClients[c] {
					t.Fatalf("client has tag %s but not in byTag", tag)
				}
			}
		}

		// Verify reverse: byTag entries should match client.tags
		for tag, tagClients := range env.relay.byTag {
			for c := range tagClients {
				if !c.tags[tag] {
					t.Fatalf("byTag has client for tag %s but client doesn't have that tag", tag)
				}
			}
		}
		env.relay.mu.RUnlock()
	}
}

// Property: After unregister, client is in no maps
func TestProp_UnregisterRemovesFromAllMaps(t *testing.T) {
	rng := rand.New(rand.NewSource(46))

	for i := 0; i < 50; i++ {
		env := newPropEnv()

		c := &Client{
			relay: env.relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 10),
		}

		env.relay.register(c)

		// Watch some tags
		tags := make([]string, rng.Intn(5)+1)
		for j := range tags {
			tags[j] = randomTag(rng)
		}
		env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: tags})

		// Unregister
		env.relay.unregister(c)

		// Check not in clients or byTag
		env.relay.mu.RLock()
		if env.relay.clients[c] {
			t.Fatalf("client still in clients map after unregister")
		}
		for _, tag := range tags {
			if tagClients, ok := env.relay.byTag[tag]; ok && tagClients[c] {
				t.Fatalf("client still in byTag[%s] after unregister", tag)
			}
		}
		env.relay.mu.RUnlock()
	}
}

// Property: event_posted delivers to exactly watchers minus sender
func TestProp_EventRoutingExactWatchers(t *testing.T) {
	rng := rand.New(rand.NewSource(48))

	for i := 0; i < 50; i++ {
		env := newPropEnv()
		tag := randomTag(rng)

		// Create clients, some watching the tag, some not
		var watchers []*Client
		var nonWatchers []*Client
		var sender *Client

		numClients := rng.Intn(10) + 3
		for j := 0; j < numClients; j++ {
			c := &Client{
				relay: env.relay,
				tags:  make(map[string]bool),
				send:  make(chan []byte, 64),
			}
			env.relay.register(c)

			if j == 0 {
				// First client is sender, also watches the tag
				sender = c
				env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: []string{tag}})
				watchers = append(watchers, c)
			} else if rng.Intn(2) == 0 {
				// Watch the tag
				env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: []string{tag}})
				watchers = append(watchers, c)
			} else {
				// Don't watch
				nonWatchers = append(nonWatchers, c)
			}
		}

		// Sender posts event
		env.relay.handleEventPosted(sender, &EventPostedMsg{Tag: tag, RKey: "rk1"})

		// Check: all watchers except sender should have received
		var wg sync.WaitGroup
		received := make(map[*Client]bool)
		var mu sync.Mutex

		for _, c := range watchers {
			wg.Add(1)
			go func(c *Client) {
				defer wg.Done()
				select {
				case <-c.send:
					mu.Lock()
					received[c] = true
					mu.Unlock()
				default:
					// No message
				}
			}(c)
		}

		for _, c := range nonWatchers {
			wg.Add(1)
			go func(c *Client) {
				defer wg.Done()
				select {
				case <-c.send:
					t.Errorf("non-watcher received message")
				default:
					// Good, no message
				}
			}(c)
		}

		wg.Wait()

		// Verify watchers (except sender) received
		for _, c := range watchers {
			if c == sender {
				if received[c] {
					t.Fatalf("sender received their own message")
				}
			} else {
				if !received[c] {
					t.Fatalf("watcher did not receive message")
				}
			}
		}
	}
}

// Property: update_tags correctly adds and removes
func TestProp_UpdateTagsCorrectness(t *testing.T) {
	rng := rand.New(rand.NewSource(49))

	for i := 0; i < 50; i++ {
		env := newPropEnv()

		c := &Client{
			relay: env.relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 10),
		}
		env.relay.register(c)

		// Start with some tags
		initialTags := make([]string, rng.Intn(5)+1)
		for j := range initialTags {
			initialTags[j] = randomTag(rng)
		}
		env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: initialTags})

		// Generate add/remove sets
		toRemove := make([]string, 0)
		toAdd := make([]string, 0)

		// Remove some existing tags
		for _, tag := range initialTags {
			if rng.Intn(2) == 0 {
				toRemove = append(toRemove, tag)
			}
		}

		// Add some new tags
		for j := 0; j < rng.Intn(3); j++ {
			toAdd = append(toAdd, randomTag(rng))
		}

		env.relay.handleUpdateTags(c, &UpdateTagsMsg{Add: toAdd, Remove: toRemove})

		// Compute expected tags
		expected := make(map[string]bool)
		for _, tag := range initialTags {
			expected[tag] = true
		}
		for _, tag := range toRemove {
			delete(expected, tag)
		}
		for _, tag := range toAdd {
			expected[tag] = true
		}

		// Verify
		env.relay.mu.RLock()
		if len(c.tags) != len(expected) {
			t.Fatalf("tag count mismatch: got %d, want %d", len(c.tags), len(expected))
		}
		for tag := range expected {
			if !c.tags[tag] {
				t.Fatalf("expected tag %s not in client.tags", tag)
			}
		}
		for tag := range c.tags {
			if !expected[tag] {
				t.Fatalf("unexpected tag %s in client.tags", tag)
			}
		}
		env.relay.mu.RUnlock()
	}
}

// Property: Relay-to-relay routing matches tags — events delivered to watchers only
func TestProp_RelayToRelayRoutingMatchesTags(t *testing.T) {
	rng := rand.New(rand.NewSource(60))

	for i := 0; i < 50; i++ {
		env := newPropEnv()

		// Create clients with random tags
		numClients := rng.Intn(10) + 2
		clients := make([]*Client, numClients)
		for j := 0; j < numClients; j++ {
			c := &Client{
				relay: env.relay,
				tags:  make(map[string]bool),
				send:  make(chan []byte, 64),
			}
			clients[j] = c
			env.relay.register(c)

			numTags := rng.Intn(5) + 1
			tags := make([]string, numTags)
			for k := range tags {
				tags[k] = randomTag(rng)
			}
			env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: tags})
		}

		// Simulate an inbound relay-to-relay event with a random tag
		eventTag := randomTag(rng)
		notification := NewEventMsg{
			Type:    "new_event",
			Tag:     eventTag,
			RKey:    "rk-prop",
			Payload: "dGVzdA==",
		}

		env.relay.deliverRelayEvent(&notification)

		// Verify: only clients watching eventTag received it
		for _, c := range clients {
			select {
			case <-c.send:
				if !c.tags[eventTag] {
					t.Fatalf("client not watching tag %s received event", eventTag)
				}
			default:
				if c.tags[eventTag] {
					t.Fatalf("client watching tag %s did NOT receive event", eventTag)
				}
			}
		}
	}
}

// Property: Payload survives round-trip through fan-out
func TestProp_PayloadPreserved(t *testing.T) {
	rng := rand.New(rand.NewSource(61))

	for i := 0; i < 50; i++ {
		done := make(chan string, 1)

		mockRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/relay/event" {
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				if p, ok := body["payload"].(string); ok {
					done <- p
				}
				w.WriteHeader(http.StatusAccepted)
			}
		}))

		env := newPropEnv()
		tag := randomTag(rng)
		payload := randomPayload(rng)

		sender := &Client{
			relay: env.relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 64),
		}
		env.relay.register(sender)

		env.relay.handleEventPosted(sender, &EventPostedMsg{
			Tag:       tag,
			RKey:      "rk-payload",
			Payload:   payload,
			RelayURLs: []string{mockRelay.URL},
		})

		select {
		case receivedPayload := <-done:
			if receivedPayload != payload {
				t.Fatalf("iteration %d: payload mismatch: sent %d bytes, received %d bytes",
					i, len(payload), len(receivedPayload))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: fan-out timed out", i)
		}
		mockRelay.Close()
	}
}

// Property: Fan-out reaches all provided URLs
func TestProp_FanOutReachesAllURLs(t *testing.T) {
	rng := rand.New(rand.NewSource(62))

	for i := 0; i < 30; i++ {
		numRelays := rng.Intn(10) + 1
		var wg sync.WaitGroup
		wg.Add(numRelays)

		servers := make([]*httptest.Server, numRelays)
		urls := make([]string, numRelays)
		for j := 0; j < numRelays; j++ {
			localWg := &wg
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/relay/event" {
					localWg.Done()
					w.WriteHeader(http.StatusAccepted)
				}
			}))
			servers[j] = srv
			urls[j] = srv.URL
		}

		env := newPropEnv()
		sender := &Client{
			relay: env.relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 64),
		}
		env.relay.register(sender)

		env.relay.handleEventPosted(sender, &EventPostedMsg{
			Tag:       randomTag(rng),
			RKey:      "rk-all",
			Payload:   "cGF5bG9hZA==",
			RelayURLs: urls,
		})

		// Wait for all relays to receive
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
			// All relays received
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: fan-out to %d relays timed out", i, numRelays)
		}

		for _, srv := range servers {
			srv.Close()
		}
	}
}

// Property: Dedup works across both local event_posted and relay-to-relay paths
func TestProp_DedupAcrossBothPaths(t *testing.T) {
	rng := rand.New(rand.NewSource(63))

	for i := 0; i < 50; i++ {
		log := slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
		verifier := newMockVerifier()
		relay := NewRelay("", "ws://test", nil, verifier, log)
		ctx, cancel := context.WithCancel(context.Background())
		relay.Run(ctx)
		defer cancel()

		srv := httptest.NewServer(relay.Handler())
		defer srv.Close()

		tag := randomTag(rng)
		rkey := "rk-" + randomTag(rng)[:8]

		// Create a watcher
		watcher := &Client{
			relay: relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 64),
		}
		relay.register(watcher)
		relay.handleWatchTags(watcher, &WatchTagsMsg{Tags: []string{tag}})

		// Path 1: local event_posted
		sender := &Client{
			relay: relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 64),
		}
		relay.register(sender)
		relay.handleEventPosted(sender, &EventPostedMsg{Tag: tag, RKey: rkey, Payload: "cGF5bG9hZA=="})

		// Path 2: relay-to-relay with same tag+rkey (no DID)
		body, _ := json.Marshal(map[string]any{
			"tag":     tag,
			"rkey":    rkey,
			"payload": "cGF5bG9hZA==",
		})
		resp, err := http.Post(srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
		if err == nil {
			resp.Body.Close()
		}

		// Watcher should receive exactly 1 message
		msgCount := 0
		for {
			select {
			case <-watcher.send:
				msgCount++
			default:
				goto done
			}
		}
	done:
		if msgCount != 1 {
			t.Fatalf("iteration %d: expected exactly 1 delivery, got %d (dedup failed across paths)", i, msgCount)
		}
	}
}

// Property: update_tags overlap — when a tag is in both add and remove, add wins
func TestProp_UpdateTagsOverlap(t *testing.T) {
	rng := rand.New(rand.NewSource(50))

	for i := 0; i < 100; i++ {
		env := newPropEnv()
		c := &Client{
			relay: env.relay,
			tags:  make(map[string]bool),
			send:  make(chan []byte, 10),
		}
		env.relay.register(c)

		// Start with some tags
		initialTags := make([]string, rng.Intn(5)+1)
		for j := range initialTags {
			initialTags[j] = randomTag(rng)
		}
		env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: initialTags})

		// Generate overlapping add/remove sets
		overlapTag := randomTag(rng) // this tag will be in BOTH add and remove
		toRemove := []string{overlapTag}
		toAdd := []string{overlapTag}

		// Add some non-overlapping ones too
		for j := 0; j < rng.Intn(3); j++ {
			toRemove = append(toRemove, initialTags[rng.Intn(len(initialTags))])
		}
		for j := 0; j < rng.Intn(3); j++ {
			toAdd = append(toAdd, randomTag(rng))
		}

		env.relay.handleUpdateTags(c, &UpdateTagsMsg{Add: toAdd, Remove: toRemove})

		// The overlap tag should be present (add runs after remove)
		env.relay.mu.RLock()
		if !c.tags[overlapTag] {
			t.Fatalf("iteration %d: overlapping tag should be present after update_tags (add wins over remove)", i)
		}
		// Also check byTag consistency
		if _, ok := env.relay.byTag[overlapTag]; !ok || !env.relay.byTag[overlapTag][c] {
			t.Fatalf("iteration %d: overlapping tag missing from byTag index", i)
		}
		env.relay.mu.RUnlock()
	}
}

// --- Helpers for relay-to-relay in property tests ---

// relayToRelayEndpoint creates a test server with the relay handler and returns its URL.
func relayToRelayEndpoint(t *testing.T, relay *Relay) string {
	t.Helper()
	srv := httptest.NewServer(relay.Handler())
	t.Cleanup(func() { srv.Close() })
	_ = strings.TrimPrefix(srv.URL, "http") // suppress unused import if needed
	return srv.URL
}
