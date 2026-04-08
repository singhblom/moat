package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// mockResolver returns pre-built DID documents for testing.
type mockResolver struct {
	mu   sync.Mutex
	docs map[string]*DIDDocument
}

func newMockResolver() *mockResolver {
	return &mockResolver{docs: make(map[string]*DIDDocument)}
}

func (r *mockResolver) Resolve(_ context.Context, did string) (*DIDDocument, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	doc, ok := r.docs[did]
	if !ok {
		return nil, fmt.Errorf("DID not found: %s", did)
	}
	return doc, nil
}

func (r *mockResolver) addDID(did string, pubKey ed25519.PublicKey, pdsURL string) {
	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 did + "#atproto",
				Type:               "Multikey",
				Controller:         did,
				PublicKeyMultibase: "z" + base64.StdEncoding.EncodeToString(pubKey),
			},
		},
		Service: []Service{
			{
				ID:              "#atproto_pds",
				Type:            "AtprotoPersonalDataServer",
				ServiceEndpoint: pdsURL,
			},
		},
	}

	r.mu.Lock()
	r.docs[did] = doc
	r.mu.Unlock()
}

// mockVerifier is a no-op verifier for tests that don't need PDS verification.
type mockVerifier struct {
	mu       sync.Mutex
	calls    []verifyCall
	failDIDs map[string]bool
}

type verifyCall struct {
	DID  string
	RKey string
	Tag  string
}

func newMockVerifier() *mockVerifier {
	return &mockVerifier{failDIDs: make(map[string]bool)}
}

func (v *mockVerifier) Verify(_ context.Context, did, rkey, tag string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls = append(v.calls, verifyCall{DID: did, RKey: rkey, Tag: tag})
	if v.failDIDs[did] {
		return fmt.Errorf("verification failed for %s", did)
	}
	return nil
}

// testEnv holds a test relay server and helper methods.
type testEnv struct {
	t        *testing.T
	relay    *Relay
	srv      *httptest.Server
	wsURL    string
	resolver *mockResolver
	verifier *mockVerifier
	cancel   context.CancelFunc
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	resolver := newMockResolver()
	verifier := newMockVerifier()
	log := slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))

	relay := NewRelay("", "ws://test-relay", resolver, verifier, log)
	ctx, cancel := context.WithCancel(context.Background())
	relay.Run(ctx)

	srv := httptest.NewServer(relay.Handler())
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	// Set publicURL so the server's challenge verification uses the same
	// base URL that test clients connect to (httptest assigns a random port).
	relay.publicURL = "ws" + strings.TrimPrefix(srv.URL, "http")

	t.Cleanup(func() {
		cancel()
		srv.Close()
	})

	return &testEnv{
		t:        t,
		relay:    relay,
		srv:      srv,
		wsURL:    wsURL,
		resolver: resolver,
		verifier: verifier,
		cancel:   cancel,
	}
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// testClient is a WebSocket client for testing.
type testClient struct {
	t    *testing.T
	conn *websocket.Conn
	did  string
	priv ed25519.PrivateKey
}

func (env *testEnv) connect(did string) *testClient {
	env.t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		env.t.Fatal(err)
	}

	env.resolver.addDID(did, pub, "https://pds.example.com")

	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL, nil)
	if err != nil {
		env.t.Fatal("dial failed:", err)
	}

	tc := &testClient{t: env.t, conn: conn, did: did, priv: priv}
	env.t.Cleanup(func() { conn.Close() })

	// Request challenge
	tc.sendJSON(map[string]any{"type": "request_challenge"})

	// Read challenge
	challenge := tc.readMsgAs("challenge")
	nonce := challenge["nonce"].(string)

	// Authenticate — sign the full connection URL (including path)
	timestamp := time.Now().Unix()
	sig := signChallengeEd25519(priv, nonce, env.wsURL, timestamp)
	tc.sendJSON(map[string]any{
		"type":       "challenge_response",
		"did":        did,
		"signature":  sig,
		"timestamp":  timestamp,
		"public_key": encodePublicKey(pub),
	})

	// Read authenticated
	tc.readMsgAs("authenticated")
	return tc
}

func (env *testEnv) connectRaw() *websocket.Conn {
	env.t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL, nil)
	if err != nil {
		env.t.Fatal("dial failed:", err)
	}
	env.t.Cleanup(func() { conn.Close() })
	return conn
}

func (tc *testClient) sendJSON(v any) {
	tc.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		tc.t.Fatal(err)
	}
	if err := tc.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		tc.t.Fatal("write failed:", err)
	}
}

func (tc *testClient) readMsg(timeout time.Duration) (map[string]any, error) {
	tc.conn.SetReadDeadline(time.Now().Add(timeout))
	_, data, err := tc.conn.ReadMessage()
	tc.conn.SetReadDeadline(time.Time{}) // always reset
	if err != nil {
		return nil, err
	}

	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (tc *testClient) readMsgAs(expectedType string) map[string]any {
	tc.t.Helper()
	msg, err := tc.readMsg(5 * time.Second)
	if err != nil {
		tc.t.Fatalf("expected %s message, got error: %v", expectedType, err)
	}
	if msg["type"] != expectedType {
		tc.t.Fatalf("expected type %s, got %s: %v", expectedType, msg["type"], msg)
	}
	return msg
}

// expectNoMsg asserts no message arrives within duration d.
// IMPORTANT: This renders the connection unusable for further reads because
// gorilla/websocket doesn't recover cleanly from read deadline timeouts.
// Only use as the last assertion on a connection.
func (tc *testClient) expectNoMsg(d time.Duration) {
	tc.t.Helper()
	tc.conn.SetReadDeadline(time.Now().Add(d))
	_, data, err := tc.conn.ReadMessage()
	if err == nil {
		tc.t.Fatalf("expected no message, got: %s", string(data))
	}
	// timeout error is expected
}

func (tc *testClient) watchTags(tags ...string) {
	tc.t.Helper()
	tc.sendJSON(map[string]any{"type": "watch_tags", "tags": tags})
}

func (tc *testClient) postEvent(tag, rkey string) {
	tc.t.Helper()
	tc.sendJSON(map[string]any{"type": "event_posted", "did": tc.did, "tag": tag, "rkey": rkey})
}

func (tc *testClient) postEventWithPayload(tag, rkey, payload string, relayURLs []string) {
	tc.t.Helper()
	tc.sendJSON(map[string]any{
		"type":       "event_posted",
		"did":        tc.did,
		"tag":        tag,
		"rkey":       rkey,
		"payload":    payload,
		"relay_urls": relayURLs,
	})
}

// --- Tests ---

func TestHealthEndpoint(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Get(env.srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestAuthFlow(t *testing.T) {
	env := newTestEnv(t)
	client := env.connect("did:plc:alice123")
	_ = client // connect already verifies auth succeeded
}

func TestAuthReject_BadSignature(t *testing.T) {
	env := newTestEnv(t)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	env.resolver.addDID("did:plc:bad", pub, "https://pds.example.com")

	conn := env.connectRaw()

	// Request challenge
	msg, _ := json.Marshal(map[string]any{"type": "request_challenge"})
	conn.WriteMessage(websocket.TextMessage, msg)

	// Read challenge
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var challenge map[string]any
	json.Unmarshal(data, &challenge)

	// Send bad signature
	msg, _ = json.Marshal(map[string]any{
		"type":       "challenge_response",
		"did":        "did:plc:bad",
		"signature":  "aW52YWxpZA==", // "invalid" in base64
		"timestamp":  time.Now().Unix(),
		"public_key": encodePublicKey(pub),
	})
	conn.WriteMessage(websocket.TextMessage, msg)

	// Expect error
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err = conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	json.Unmarshal(data, &resp)
	if resp["type"] != "error" {
		t.Fatalf("expected error, got %v", resp)
	}
}

func TestAuthReject_ExpiredTimestamp(t *testing.T) {
	env := newTestEnv(t)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env.resolver.addDID("did:plc:expired", pub, "https://pds.example.com")

	conn := env.connectRaw()

	// Request challenge
	msg, _ := json.Marshal(map[string]any{"type": "request_challenge"})
	conn.WriteMessage(websocket.TextMessage, msg)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, _ := conn.ReadMessage()
	var challenge map[string]any
	json.Unmarshal(data, &challenge)
	nonce := challenge["nonce"].(string)

	// Use timestamp from 2 minutes ago
	timestamp := time.Now().Add(-2 * time.Minute).Unix()
	sig := signChallengeEd25519(priv, nonce, env.wsURL, timestamp)

	msg, _ = json.Marshal(map[string]any{
		"type":       "challenge_response",
		"did":        "did:plc:expired",
		"signature":  sig,
		"timestamp":  timestamp,
		"public_key": encodePublicKey(pub),
	})
	conn.WriteMessage(websocket.TextMessage, msg)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, _ = conn.ReadMessage()
	var resp map[string]any
	json.Unmarshal(data, &resp)
	if resp["type"] != "error" {
		t.Fatalf("expected error for expired timestamp, got %v", resp)
	}
}

func TestWatchAndNotify(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	alice.watchTags("aabbccdd00112233aabbccdd00112233")

	// Small delay for registration to process
	time.Sleep(50 * time.Millisecond)

	bob.postEvent("aabbccdd00112233aabbccdd00112233", "abc123")

	msg := alice.readMsgAs("new_event")
	if msg["tag"] != "aabbccdd00112233aabbccdd00112233" {
		t.Fatalf("wrong tag: %v", msg["tag"])
	}
	if msg["rkey"] != "abc123" {
		t.Fatalf("wrong rkey: %v", msg["rkey"])
	}
}

func TestUpdateTags(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	tag1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	tag2 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"

	alice.watchTags(tag1)
	time.Sleep(50 * time.Millisecond)

	// Update: remove tag1, add tag2
	alice.sendJSON(map[string]any{"type": "update_tags", "remove": []string{tag1}, "add": []string{tag2}})
	time.Sleep(50 * time.Millisecond)

	// Post to new tag - alice should receive
	bob.postEvent(tag2, "rk2")
	msg := alice.readMsgAs("new_event")
	if msg["tag"] != tag2 {
		t.Fatalf("expected tag2, got %v", msg["tag"])
	}

	// Post to old tag - alice should NOT receive (use expectNoMsg last)
	bob.postEvent(tag1, "rk1")
	alice.expectNoMsg(200 * time.Millisecond)
}

func TestMultiDevice(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"

	alice1 := env.connect("did:plc:alice")
	alice2 := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	alice1.watchTags(tag)
	alice2.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	bob.postEvent(tag, "rk1")

	// Both Alice devices should receive
	alice1.readMsgAs("new_event")
	alice2.readMsgAs("new_event")
}

func TestSelfNotifyOtherDevice(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"

	alice1 := env.connect("did:plc:alice")
	alice2 := env.connect("did:plc:alice")

	alice1.watchTags(tag)
	alice2.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	// Alice posts from device 1
	alice1.postEvent(tag, "rk1")

	// Device 2 should receive notification
	alice2.readMsgAs("new_event")

	// Device 1 (sender) should NOT receive
	alice1.expectNoMsg(200 * time.Millisecond)
}

func TestDedup(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	// Different rkey should go through
	bob.postEvent(tag, "rk-first")
	msg := alice.readMsgAs("new_event")
	if msg["rkey"] != "rk-first" {
		t.Fatalf("expected rk-first, got %v", msg["rkey"])
	}

	// Post same event twice rapidly — only first should deliver
	bob.postEvent(tag, "rk-dup")
	bob.postEvent(tag, "rk-dup")

	alice.readMsgAs("new_event")
	// Second one should be suppressed — expectNoMsg as last assertion
	alice.expectNoMsg(200 * time.Millisecond)
}

func TestDisconnectBuffer(t *testing.T) {
	env := newTestEnv(t)
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"

	// Alice connects, watches tag, then disconnects
	alice1 := env.connect("did:plc:alice")
	alice1.watchTags(tag)
	time.Sleep(50 * time.Millisecond)
	alice1.conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Bob posts while Alice is disconnected
	bob.postEvent(tag, "buffered-rk")
	time.Sleep(100 * time.Millisecond)

	// Alice reconnects and re-registers the same tag — buffer flushes on watch_tags.
	alice2 := env.connect("did:plc:alice")
	alice2.watchTags(tag)

	// Should receive buffered notification
	msg := alice2.readMsgAs("new_event")
	if msg["rkey"] != "buffered-rk" {
		t.Fatalf("expected buffered-rk, got %v", msg["rkey"])
	}
}

func TestDisconnectBufferExpiry(t *testing.T) {
	env := newTestEnv(t)
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"

	// Alice connects, watches tag, then disconnects
	alice1 := env.connect("did:plc:alice")
	alice1.watchTags(tag)
	time.Sleep(50 * time.Millisecond)
	alice1.conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Manually expire the buffer (keyed by tag, not by DID).
	env.relay.bufferMu.Lock()
	if buf, ok := env.relay.buffers[tag]; ok {
		buf.expiresAt = time.Now().Add(-1 * time.Second)
	}
	env.relay.bufferMu.Unlock()
	env.relay.cleanupBuffers()

	// Bob posts after buffer expired
	bob.postEvent(tag, "late-rk")
	time.Sleep(100 * time.Millisecond)

	// Alice reconnects and re-registers the tag — no buffer exists so nothing is flushed.
	alice2 := env.connect("did:plc:alice")
	alice2.watchTags(tag)
	alice2.expectNoMsg(200 * time.Millisecond)
}

func TestAsyncVerification(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	bob.postEvent(tag, "rk1")
	alice.readMsgAs("new_event")

	// Give async verification time to complete
	time.Sleep(200 * time.Millisecond)

	env.verifier.mu.Lock()
	defer env.verifier.mu.Unlock()

	if len(env.verifier.calls) != 1 {
		t.Fatalf("expected 1 verify call, got %d", len(env.verifier.calls))
	}
	call := env.verifier.calls[0]
	if call.DID != "did:plc:bob" || call.RKey != "rk1" || call.Tag != tag {
		t.Fatalf("unexpected verify call: %+v", call)
	}
}

func TestPushTokenRegistration(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")

	alice.sendJSON(map[string]any{
		"type":     "register_push",
		"platform": "fcm",
		"token":    "test-token-123",
	})

	// Give time for message processing
	time.Sleep(100 * time.Millisecond)

	// Verify via relay internals
	env.relay.mu.RLock()
	defer env.relay.mu.RUnlock()

	var found bool
	for client := range env.relay.clients {
		if client.pushToken != nil &&
			client.pushToken.Platform == "fcm" &&
			client.pushToken.Token == "test-token-123" {
			found = true
		}
	}
	if !found {
		t.Fatal("push token not registered")
	}
}

func TestPreAuthRejectsOtherMessages(t *testing.T) {
	env := newTestEnv(t)
	conn := env.connectRaw()

	// Try sending watch_tags before auth
	msg, _ := json.Marshal(map[string]any{"type": "watch_tags", "tags": []string{"abc"}})
	conn.WriteMessage(websocket.TextMessage, msg)

	// Should get error
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	json.Unmarshal(data, &resp)
	if resp["type"] != "error" {
		t.Fatalf("expected error, got %v", resp)
	}
	if errMsg := resp["message"].(string); !strings.Contains(errMsg, "authenticate") {
		t.Fatalf("expected auth error message, got: %s", errMsg)
	}
}

func TestChallengeResponseWithoutRequest(t *testing.T) {
	env := newTestEnv(t)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env.resolver.addDID("did:plc:noRequest", pub, "https://pds.example.com")

	conn := env.connectRaw()

	// Try to send challenge_response without requesting challenge first
	timestamp := time.Now().Unix()
	sig := signChallengeEd25519(priv, "fake-nonce", env.wsURL, timestamp)

	msg, _ := json.Marshal(map[string]any{
		"type":       "challenge_response",
		"did":        "did:plc:noRequest",
		"signature":  sig,
		"timestamp":  timestamp,
		"public_key": encodePublicKey(pub),
	})
	conn.WriteMessage(websocket.TextMessage, msg)

	// Should get error about requesting challenge first
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	json.Unmarshal(data, &resp)
	if resp["type"] != "error" {
		t.Fatalf("expected error, got %v", resp)
	}
	if !strings.Contains(resp["message"].(string), "request challenge") {
		t.Fatalf("expected 'must request challenge' error, got: %v", resp["message"])
	}
}

// --- Ticket messages should be rejected (removed feature) ---

func TestTicketAuthRejected(t *testing.T) {
	env := newTestEnv(t)
	conn := env.connectRaw()

	ticket := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	msg, _ := json.Marshal(map[string]any{"type": "ticket_auth", "ticket": ticket})
	conn.WriteMessage(websocket.TextMessage, msg)

	// Should get error — ticket_auth is no longer a valid message type
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	json.Unmarshal(data, &resp)
	if resp["type"] != "error" {
		t.Fatalf("expected error for ticket_auth, got %v", resp)
	}
}

func TestTicketMessagesRejectedPostAuth(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")

	// register_ticket should be rejected
	alice.sendJSON(map[string]any{
		"type":   "register_ticket",
		"ticket": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	msg := alice.readMsgAs("error")
	if !strings.Contains(msg["message"].(string), "unknown") {
		t.Fatalf("expected unknown message error, got: %v", msg["message"])
	}
}

// --- Payload delivery tests ---

func TestEventPostedWithPayload(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	payload := base64.StdEncoding.EncodeToString([]byte("encrypted-ciphertext-here"))

	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	bob.postEventWithPayload(tag, "rk1", payload, nil)

	msg := alice.readMsgAs("new_event")
	if msg["tag"] != tag {
		t.Fatalf("wrong tag: %v", msg["tag"])
	}
	if msg["rkey"] != "rk1" {
		t.Fatalf("wrong rkey: %v", msg["rkey"])
	}
	if msg["payload"] != payload {
		t.Fatalf("expected payload %q, got %v", payload, msg["payload"])
	}
}

func TestEventPostedPayloadInDisconnectBuffer(t *testing.T) {
	env := newTestEnv(t)
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	payload := base64.StdEncoding.EncodeToString([]byte("buffered-payload"))

	// Alice connects, watches tag, then disconnects
	alice1 := env.connect("did:plc:alice")
	alice1.watchTags(tag)
	time.Sleep(50 * time.Millisecond)
	alice1.conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Bob posts with payload while Alice is disconnected
	bob.postEventWithPayload(tag, "rk-buf", payload, nil)
	time.Sleep(100 * time.Millisecond)

	// Alice reconnects and re-registers the tag — buffer flushes on watch_tags.
	alice2 := env.connect("did:plc:alice")
	alice2.watchTags(tag)

	// Should receive buffered notification with payload
	msg := alice2.readMsgAs("new_event")
	if msg["rkey"] != "rk-buf" {
		t.Fatalf("expected rk-buf, got %v", msg["rkey"])
	}
	if msg["payload"] != payload {
		t.Fatalf("expected payload in buffered notification, got %v", msg["payload"])
	}
}

// --- Relay-to-relay tests ---

func TestRelayToRelay_BasicDelivery(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	payload := base64.StdEncoding.EncodeToString([]byte("relay-to-relay-payload"))

	alice := env.connect("did:plc:alice")
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	// Simulate inbound relay-to-relay POST (no DID — untrustworthy on unauthenticated endpoint)
	body, _ := json.Marshal(map[string]any{
		"tag":     tag,
		"rkey":    "rk-r2r",
		"payload": payload,
	})
	resp, err := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Alice should receive the event
	msg := alice.readMsgAs("new_event")
	if msg["tag"] != tag {
		t.Fatalf("wrong tag: %v", msg["tag"])
	}
	if msg["rkey"] != "rk-r2r" {
		t.Fatalf("wrong rkey: %v", msg["rkey"])
	}
	// No DID field in new_event — the relay no longer forwards sender identity.
	if _, hasDID := msg["did"]; hasDID {
		t.Fatalf("expected no DID field in new_event, got %v", msg["did"])
	}
	if msg["payload"] != payload {
		t.Fatalf("wrong payload: %v", msg["payload"])
	}
}

func TestRelayToRelay_NoMatchingTag(t *testing.T) {
	env := newTestEnv(t)

	alice := env.connect("did:plc:alice")
	alice.watchTags("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
	time.Sleep(50 * time.Millisecond)

	// POST with a different tag
	body, _ := json.Marshal(map[string]any{
		"tag":     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"rkey":    "rk1",
		"payload": "cGF5bG9hZA==",
	})
	resp, err := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}

	// Alice should NOT receive anything
	alice.expectNoMsg(200 * time.Millisecond)
}

func TestRelayToRelay_MultipleClients(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"

	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	alice.watchTags(tag)
	bob.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	// Inbound relay-to-relay event
	body, _ := json.Marshal(map[string]any{
		"tag":     tag,
		"rkey":    "rk-multi",
		"payload": "cGF5bG9hZA==",
	})
	resp, err := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Both should receive
	alice.readMsgAs("new_event")
	bob.readMsgAs("new_event")
}

func TestRelayToRelay_Dedup(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	alice := env.connect("did:plc:alice")
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	body, _ := json.Marshal(map[string]any{
		"tag":     tag,
		"rkey":    "rk-dup",
		"payload": "cGF5bG9hZA==",
	})

	// POST twice
	resp1, _ := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
	resp1.Body.Close()
	// Need a fresh reader for the second POST
	body2, _ := json.Marshal(map[string]any{
		"tag":     tag,
		"rkey":    "rk-dup",
		"did":     "did:plc:bob",
		"payload": "cGF5bG9hZA==",
	})
	resp2, _ := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body2))
	resp2.Body.Close()

	// Alice should receive only once
	alice.readMsgAs("new_event")
	alice.expectNoMsg(200 * time.Millisecond)
}

func TestRelayToRelay_DisconnectBuffer(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	payload := base64.StdEncoding.EncodeToString([]byte("buffered-r2r"))

	// Alice connects, watches tag, then disconnects
	alice1 := env.connect("did:plc:alice")
	alice1.watchTags(tag)
	time.Sleep(50 * time.Millisecond)
	alice1.conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Relay-to-relay event while Alice is disconnected
	body, _ := json.Marshal(map[string]any{
		"tag":     tag,
		"rkey":    "rk-r2r-buf",
		"payload": payload,
	})
	resp, _ := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)

	// Alice reconnects and re-registers the tag — buffer flushes on watch_tags.
	alice2 := env.connect("did:plc:alice")
	alice2.watchTags(tag)

	// Should receive buffered notification with payload
	msg := alice2.readMsgAs("new_event")
	if msg["rkey"] != "rk-r2r-buf" {
		t.Fatalf("expected rk-r2r-buf, got %v", msg["rkey"])
	}
	if msg["payload"] != payload {
		t.Fatalf("expected payload in buffer, got %v", msg["payload"])
	}
}

// TestRateLimiting_DIDFromEnvelope verifies that the rate limiter keys by the DID
// supplied in the event_posted envelope (not by a connection-level field).
func TestRateLimiting_DIDFromEnvelope(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	// Record 3 failures for bob's DID to trigger the rate limit.
	env.relay.rateLimiter.RecordFailure("did:plc:bob")
	env.relay.rateLimiter.RecordFailure("did:plc:bob")
	env.relay.rateLimiter.RecordFailure("did:plc:bob")

	// Bob posts an event with his DID in the envelope.
	bob.postEvent(tag, "rate-limited-rk")

	// Alice should NOT receive it — the envelope DID is rate-limited.
	alice.expectNoMsg(200 * time.Millisecond)
}

// TestDisconnectBuffer_FlushByTag verifies that the disconnect buffer is keyed
// by tag rather than by DID: a reconnecting client with any DID that watches the
// same tag receives events buffered while the tag was unwatched.
func TestDisconnectBuffer_FlushByTag(t *testing.T) {
	env := newTestEnv(t)
	bob := env.connect("did:plc:bob")

	tag := "aabbccddaabbccddaabbccddaabbccdd"

	// Alice connects, watches tag, then disconnects.
	alice := env.connect("did:plc:alice")
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)
	alice.conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Bob posts while Alice is disconnected.
	bob.postEvent(tag, "rk-tag-flush")
	time.Sleep(100 * time.Millisecond)

	// Carol — a different DID — reconnects and watches the same tag.
	carol := env.connect("did:plc:carol")
	carol.watchTags(tag)

	// Carol receives the buffered event: buffer flushes on tag match, not DID match.
	msg := carol.readMsgAs("new_event")
	if msg["rkey"] != "rk-tag-flush" {
		t.Fatalf("expected rk-tag-flush, got %v", msg["rkey"])
	}
}

func TestRelayToRelay_NoAsyncVerification(t *testing.T) {
	env := newTestEnv(t)

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	alice := env.connect("did:plc:alice")
	alice.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	body, _ := json.Marshal(map[string]any{
		"tag":     tag,
		"rkey":    "rk-verify",
		"payload": "cGF5bG9hZA==",
	})
	resp, _ := http.Post(env.srv.URL+"/relay/event", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	// Alice should receive the event
	alice.readMsgAs("new_event")

	// No async verification should happen — relay-to-relay has no DID to verify
	time.Sleep(200 * time.Millisecond)

	env.verifier.mu.Lock()
	callCount := len(env.verifier.calls)
	env.verifier.mu.Unlock()

	if callCount != 0 {
		t.Fatalf("expected 0 verify calls from relay-to-relay path (no DID), got %d", callCount)
	}
}

func TestEventPosted_FanOut(t *testing.T) {
	env := newTestEnv(t)

	// Set up mock HTTP servers to receive fan-out
	var mu sync.Mutex
	received := make(map[string]map[string]any)

	mockRelay1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/relay/event" {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			received["relay1"] = body
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer mockRelay1.Close()

	mockRelay2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/relay/event" {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			received["relay2"] = body
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer mockRelay2.Close()

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	payload := base64.StdEncoding.EncodeToString([]byte("fanout-payload"))

	bob := env.connect("did:plc:bob")
	bob.postEventWithPayload(tag, "rk-fan", payload, []string{mockRelay1.URL, mockRelay2.URL})

	// Give fan-out time to complete
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 2 {
		t.Fatalf("expected fan-out to 2 relays, got %d", len(received))
	}
	for name, body := range received {
		if body["tag"] != tag {
			t.Fatalf("%s: wrong tag %v", name, body["tag"])
		}
		if body["rkey"] != "rk-fan" {
			t.Fatalf("%s: wrong rkey %v", name, body["rkey"])
		}
		// No DID should be included in relay-to-relay fan-out
		if _, hasDID := body["did"]; hasDID {
			t.Fatalf("%s: relay-to-relay should not contain DID, got %v", name, body["did"])
		}
		if body["payload"] != payload {
			t.Fatalf("%s: wrong payload %v", name, body["payload"])
		}
	}
}

func TestEventPosted_FanOutTimeout(t *testing.T) {
	env := newTestEnv(t)

	// One relay is responsive, one hangs
	var mu sync.Mutex
	var fastReceived bool

	fastRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/relay/event" {
			mu.Lock()
			fastReceived = true
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer fastRelay.Close()

	// Use a URL that will connection-refuse immediately
	deadURL := "http://127.0.0.1:1" // port 1 is not listening

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	bob := env.connect("did:plc:bob")
	bob.postEventWithPayload(tag, "rk-timeout", "cGF5bG9hZA==", []string{fastRelay.URL, deadURL})

	// Give fan-out time — fast relay should complete even though dead one fails
	time.Sleep(1 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if !fastReceived {
		t.Fatal("fast relay should have received fan-out despite slow relay")
	}
}

func TestEventPosted_FanOutPlusLocalDelivery(t *testing.T) {
	env := newTestEnv(t)

	var mu sync.Mutex
	var relayReceived bool

	mockRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/relay/event" {
			mu.Lock()
			relayReceived = true
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer mockRelay.Close()

	tag := "aabbccddaabbccddaabbccddaabbccdd"
	payload := base64.StdEncoding.EncodeToString([]byte("local-and-remote"))

	// Alice has two devices on the same relay
	alice1 := env.connect("did:plc:alice")
	alice2 := env.connect("did:plc:alice")
	alice1.watchTags(tag)
	alice2.watchTags(tag)
	time.Sleep(50 * time.Millisecond)

	// Alice device 1 posts — device 2 should get local delivery AND fan-out should happen
	alice1.postEventWithPayload(tag, "rk-both", payload, []string{mockRelay.URL})

	// Device 2 should receive locally
	msg := alice2.readMsgAs("new_event")
	if msg["payload"] != payload {
		t.Fatalf("expected payload in local delivery, got %v", msg["payload"])
	}

	// Fan-out should also have happened
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !relayReceived {
		t.Fatal("expected fan-out to remote relay")
	}
}

func TestNormalizeRelayURL(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"ws://127.0.0.1:8080/ws", "http://127.0.0.1:8080"},
		{"wss://relay.example.com/ws", "https://relay.example.com"},
		{"ws://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"wss://relay.example.com", "https://relay.example.com"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"https://relay.example.com", "https://relay.example.com"},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
	}
	for _, tt := range tests {
		got := normalizeRelayURL(tt.input)
		if got != tt.want {
			t.Errorf("normalizeRelayURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
