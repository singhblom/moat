package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
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

func randomTicket(rng *rand.Rand) string {
	b := make([]byte, 32)
	rng.Read(b)
	return hex.EncodeToString(b)
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

// Property: Ticket can only be revoked by owner
func TestProp_TicketRevokeOnlyByOwner(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < 100; i++ {
		env := newPropEnv()
		ticket := randomTicket(rng)
		ownerDID := randomDID(rng)
		otherDID := randomDID(rng)

		// Register ticket
		env.relay.ticketsMu.Lock()
		env.relay.tickets[ticket] = ownerDID
		env.relay.ticketsMu.Unlock()

		// Create mock clients
		ownerClient := &Client{did: ownerDID, authMode: AuthModeSender, send: make(chan []byte, 10)}
		otherClient := &Client{did: otherDID, authMode: AuthModeSender, send: make(chan []byte, 10)}

		// Other client tries to revoke - should fail
		env.relay.handleRevokeTicket(otherClient, &RevokeTicketMsg{Ticket: ticket})

		env.relay.ticketsMu.RLock()
		_, stillExists := env.relay.tickets[ticket]
		env.relay.ticketsMu.RUnlock()

		if !stillExists {
			t.Fatalf("ticket was revoked by non-owner")
		}

		// Owner revokes - should succeed
		env.relay.handleRegisterTicket(ownerClient, &RegisterTicketMsg{Ticket: ticket}) // re-register to clear state
		env.relay.handleRevokeTicket(ownerClient, &RevokeTicketMsg{Ticket: ticket})

		env.relay.ticketsMu.RLock()
		_, existsAfterOwnerRevoke := env.relay.tickets[ticket]
		env.relay.ticketsMu.RUnlock()

		if existsAfterOwnerRevoke {
			t.Fatalf("ticket was NOT revoked by owner")
		}
	}
}

// Property: Revoked ticket cannot authenticate
func TestProp_RevokedTicketCannotAuth(t *testing.T) {
	rng := rand.New(rand.NewSource(43))

	for i := 0; i < 100; i++ {
		env := newPropEnv()
		ticket := randomTicket(rng)
		ownerDID := randomDID(rng)

		// Register then revoke
		env.relay.ticketsMu.Lock()
		env.relay.tickets[ticket] = ownerDID
		env.relay.ticketsMu.Unlock()

		ownerClient := &Client{did: ownerDID, authMode: AuthModeSender, send: make(chan []byte, 10)}
		env.relay.handleRevokeTicket(ownerClient, &RevokeTicketMsg{Ticket: ticket})

		// Try to authenticate with revoked ticket
		recipientClient := &Client{send: make(chan []byte, 10)}
		err := env.relay.authenticateTicket(recipientClient, ticket)

		if err == nil {
			t.Fatalf("revoked ticket was accepted for auth")
		}
	}
}

// Property: Ticket registration is idempotent for same owner
func TestProp_TicketRegistrationIdempotent(t *testing.T) {
	rng := rand.New(rand.NewSource(44))

	for i := 0; i < 100; i++ {
		env := newPropEnv()
		ticket := randomTicket(rng)
		ownerDID := randomDID(rng)

		ownerClient := &Client{did: ownerDID, authMode: AuthModeSender, send: make(chan []byte, 10)}

		// Register multiple times
		for j := 0; j < 5; j++ {
			env.relay.handleRegisterTicket(ownerClient, &RegisterTicketMsg{Ticket: ticket})
		}

		env.relay.ticketsMu.RLock()
		owner, exists := env.relay.tickets[ticket]
		env.relay.ticketsMu.RUnlock()

		if !exists {
			t.Fatalf("ticket should exist after registration")
		}
		if owner != ownerDID {
			t.Fatalf("ticket owner mismatch: got %s, want %s", owner, ownerDID)
		}
	}
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
				relay:    env.relay,
				did:      randomDID(rng),
				authMode: AuthModeSender,
				tags:     make(map[string]bool),
				send:     make(chan []byte, 10),
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

		did := randomDID(rng)
		c := &Client{
			relay:    env.relay,
			did:      did,
			authMode: AuthModeSender,
			tags:     make(map[string]bool),
			send:     make(chan []byte, 10),
		}

		env.relay.register(c)
		env.relay.registerDID(c, did)

		// Watch some tags
		tags := make([]string, rng.Intn(5)+1)
		for j := range tags {
			tags[j] = randomTag(rng)
		}
		env.relay.handleWatchTags(c, &WatchTagsMsg{Tags: tags})

		// Unregister
		env.relay.unregister(c)

		// Check not in clients
		env.relay.mu.RLock()
		if env.relay.clients[c] {
			t.Fatalf("client still in clients map after unregister")
		}

		// Check not in byDID
		if didClients, ok := env.relay.byDID[did]; ok && didClients[c] {
			t.Fatalf("client still in byDID map after unregister")
		}

		// Check not in byTag
		for _, tag := range tags {
			if tagClients, ok := env.relay.byTag[tag]; ok && tagClients[c] {
				t.Fatalf("client still in byTag[%s] after unregister", tag)
			}
		}
		env.relay.mu.RUnlock()
	}
}

// Property: byDID only contains sender-authenticated clients
func TestProp_ByDIDOnlySenders(t *testing.T) {
	rng := rand.New(rand.NewSource(47))

	for i := 0; i < 50; i++ {
		env := newPropEnv()

		// Create mix of senders and recipients
		for j := 0; j < 10; j++ {
			if rng.Intn(2) == 0 {
				// Sender
				did := randomDID(rng)
				c := &Client{
					relay:    env.relay,
					did:      did,
					authMode: AuthModeSender,
					tags:     make(map[string]bool),
					send:     make(chan []byte, 10),
				}
				env.relay.register(c)
				env.relay.registerDID(c, did)
			} else {
				// Recipient
				ticket := randomTicket(rng)
				c := &Client{
					relay:    env.relay,
					ticket:   ticket,
					authMode: AuthModeRecipient,
					tags:     make(map[string]bool),
					send:     make(chan []byte, 10),
				}
				env.relay.register(c)
				// Recipients should NOT be in byDID
			}
		}

		// Verify: all clients in byDID should be senders
		env.relay.mu.RLock()
		for did, didClients := range env.relay.byDID {
			for c := range didClients {
				if c.authMode != AuthModeSender {
					t.Fatalf("non-sender in byDID[%s]", did)
				}
				if c.did != did {
					t.Fatalf("client.did mismatch in byDID: got %s, want %s", c.did, did)
				}
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
				relay:    env.relay,
				did:      randomDID(rng),
				authMode: AuthModeSender,
				tags:     make(map[string]bool),
				send:     make(chan []byte, 64),
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
			relay:    env.relay,
			did:      randomDID(rng),
			authMode: AuthModeSender,
			tags:     make(map[string]bool),
			send:     make(chan []byte, 10),
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
