package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
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
	raw := append([]byte{0xed, 0x01}, pubKey...)
	multibase := "z" + encodeBase58(raw)

	doc := &DIDDocument{
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 did + "#atproto",
				Type:               "Multikey",
				Controller:         did,
				PublicKeyMultibase: multibase,
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

	relay := NewRelay("ws://test-relay", resolver, verifier, log)
	ctx, cancel := context.WithCancel(context.Background())
	relay.Run(ctx)

	srv := httptest.NewServer(relay.Handler())
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

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

	// Read challenge
	challenge := tc.readMsgAs("challenge")
	nonce := challenge["nonce"].(string)

	// Authenticate
	timestamp := time.Now().Unix()
	sig := signChallengeEd25519(priv, nonce, "ws://test-relay", timestamp)
	tc.sendJSON(map[string]any{
		"type":      "challenge_response",
		"did":       did,
		"signature": sig,
		"timestamp": timestamp,
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
	tc.sendJSON(map[string]any{"type": "event_posted", "tag": tag, "rkey": rkey})
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

	// Read challenge
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var challenge map[string]any
	json.Unmarshal(data, &challenge)

	// Send bad signature
	msg, _ := json.Marshal(map[string]any{
		"type":      "challenge_response",
		"did":       "did:plc:bad",
		"signature": "aW52YWxpZA==", // "invalid" in base64
		"timestamp": time.Now().Unix(),
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

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, _ := conn.ReadMessage()
	var challenge map[string]any
	json.Unmarshal(data, &challenge)
	nonce := challenge["nonce"].(string)

	// Use timestamp from 2 minutes ago
	timestamp := time.Now().Add(-2 * time.Minute).Unix()
	sig := signChallengeEd25519(priv, nonce, "ws://test-relay", timestamp)

	msg, _ := json.Marshal(map[string]any{
		"type":      "challenge_response",
		"did":       "did:plc:expired",
		"signature": sig,
		"timestamp": timestamp,
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
	if msg["did"] != "did:plc:bob" {
		t.Fatalf("wrong did: %v", msg["did"])
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

	// Alice reconnects
	alice2 := env.connect("did:plc:alice")

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

	// Manually expire the buffer
	env.relay.bufferMu.Lock()
	if buf, ok := env.relay.buffers["did:plc:alice"]; ok {
		buf.expiresAt = time.Now().Add(-1 * time.Second)
	}
	env.relay.bufferMu.Unlock()
	env.relay.cleanupBuffers()

	// Bob posts after buffer expired
	bob.postEvent(tag, "late-rk")
	time.Sleep(100 * time.Millisecond)

	// Alice reconnects - should NOT receive buffered notification
	alice2 := env.connect("did:plc:alice")
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
		if client.did == "did:plc:alice" && client.pushToken != nil {
			if client.pushToken.Platform == "fcm" && client.pushToken.Token == "test-token-123" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("push token not registered")
	}
}

func TestPreAuthRejectsOtherMessages(t *testing.T) {
	env := newTestEnv(t)
	conn := env.connectRaw()

	// Read challenge
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.ReadMessage()

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
	if msg := resp["message"].(string); !strings.Contains(msg, "authenticate") {
		t.Fatalf("expected auth error message, got: %s", msg)
	}
}
