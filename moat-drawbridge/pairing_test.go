package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// pairURL returns the /pair WebSocket URL for a test environment.
func (env *testEnv) pairURL() string {
	return "ws" + env.srv.URL[len("http"):] + "/pair"
}

// pairClient is a test helper for the /pair WebSocket connection.
type pairClient struct {
	t    *testing.T
	conn *websocket.Conn
}

// dialPair opens a /pair connection and sends pair_attach{token}.
// The connection is registered for cleanup on t.Cleanup.
func (env *testEnv) dialPair(token string) *pairClient {
	env.t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(env.pairURL(), nil)
	if err != nil {
		env.t.Fatal("pair dial failed:", err)
	}
	env.t.Cleanup(func() { conn.Close() })

	data, _ := json.Marshal(PairAttachMsg{Type: "pair_attach", Token: token})
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		env.t.Fatal("pair_attach write failed:", err)
	}

	return &pairClient{t: env.t, conn: conn}
}

func (pc *pairClient) expectPaired(timeout time.Duration) {
	pc.t.Helper()
	pc.conn.SetReadDeadline(time.Now().Add(timeout))
	_, data, err := pc.conn.ReadMessage()
	pc.conn.SetReadDeadline(time.Time{})
	if err != nil {
		pc.t.Fatal("expected paired msg, got error:", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		pc.t.Fatal("paired msg unmarshal:", err)
	}
	if msg["type"] != "paired" {
		pc.t.Fatalf("expected type=paired, got %v", msg["type"])
	}
}

func (pc *pairClient) writeBinary(data []byte) {
	pc.t.Helper()
	if err := pc.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		pc.t.Fatal("binary write failed:", err)
	}
}

func (pc *pairClient) expectBinary(timeout time.Duration) []byte {
	pc.t.Helper()
	pc.conn.SetReadDeadline(time.Now().Add(timeout))
	mt, data, err := pc.conn.ReadMessage()
	pc.conn.SetReadDeadline(time.Time{})
	if err != nil {
		pc.t.Fatal("expected binary frame, got error:", err)
	}
	if mt != websocket.BinaryMessage {
		pc.t.Fatalf("expected binary frame, got message type %d", mt)
	}
	return data
}

func (pc *pairClient) expectClose(timeout time.Duration) {
	pc.t.Helper()
	pc.conn.SetReadDeadline(time.Now().Add(timeout))
	_, _, err := pc.conn.ReadMessage()
	pc.conn.SetReadDeadline(time.Time{})
	if err == nil {
		pc.t.Fatal("expected connection to be closed, but read succeeded")
	}
}

// doHandshake performs the full pair offer/join handshake over the main WS and
// returns the pair URL. Both alice and bob must be authenticated test clients.
func doHandshake(t *testing.T, alice, bob *testClient, token string) string {
	t.Helper()

	alice.sendJSON(map[string]any{"type": "pair_offer", "token": token})
	pending := alice.readMsgAs("pair_pending")
	if pending["token"] != token {
		t.Fatalf("pair_pending token mismatch: want %q got %v", token, pending["token"])
	}

	bob.sendJSON(map[string]any{"type": "pair_join", "token": token})

	aliceReady := alice.readMsgAs("pair_ready")
	bobReady := bob.readMsgAs("pair_ready")

	pairURL, _ := aliceReady["pair_url"].(string)
	if pairURL == "" {
		t.Fatal("pair_url missing from pair_ready")
	}
	if aliceReady["pair_url"] != bobReady["pair_url"] {
		t.Fatal("alice and bob got different pair_urls")
	}
	if aliceReady["token"] != token || bobReady["token"] != token {
		t.Fatal("token mismatch in pair_ready")
	}
	return pairURL
}

func TestPairing_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")

	token := "aabbccdd" + fmt.Sprintf("%056x", 0) // 64-char hex token

	doHandshake(t, alice, bob, token)

	// Both open the pair WS. Dial and send pair_attach without blocking on
	// the read — the server goroutine blocks until both sides have attached.
	alicePair := env.dialPair(token)
	bobPair := env.dialPair(token)

	alicePair.expectPaired(5 * time.Second)
	bobPair.expectPaired(5 * time.Second)

	// Exchange binary frames in both directions.
	alicePair.writeBinary([]byte("hello from alice"))
	got := bobPair.expectBinary(5 * time.Second)
	if string(got) != "hello from alice" {
		t.Fatalf("bob got %q, want %q", got, "hello from alice")
	}

	bobPair.writeBinary([]byte("hello from bob"))
	got = alicePair.expectBinary(5 * time.Second)
	if string(got) != "hello from bob" {
		t.Fatalf("alice got %q, want %q", got, "hello from bob")
	}
}

func TestPairing_MultipleFrames(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	token := "deadbeef" + fmt.Sprintf("%056x", 0)

	doHandshake(t, alice, bob, token)
	alicePair := env.dialPair(token)
	bobPair := env.dialPair(token)
	alicePair.expectPaired(5 * time.Second)
	bobPair.expectPaired(5 * time.Second)

	const N = 20
	// Alice sends N frames; Bob receives them all.
	for i := 0; i < N; i++ {
		alicePair.writeBinary([]byte(fmt.Sprintf("frame-%d", i)))
	}
	for i := 0; i < N; i++ {
		got := bobPair.expectBinary(5 * time.Second)
		if string(got) != fmt.Sprintf("frame-%d", i) {
			t.Fatalf("frame %d: got %q", i, got)
		}
	}
}

func TestPairing_AttachBeforeJoin(t *testing.T) {
	// Alice opens the pair WS before Bob has even sent pair_join.
	// The server goroutine blocks in Attach and must stay blocked until Bob
	// joins and opens his own pair WS.
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	token := "cafebabe" + fmt.Sprintf("%056x", 0)

	alice.sendJSON(map[string]any{"type": "pair_offer", "token": token})
	alice.readMsgAs("pair_pending")

	// Alice opens pair WS immediately, before pair_join from Bob.
	alicePairConn, _, err := websocket.DefaultDialer.Dial(env.pairURL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { alicePairConn.Close() })
	attachData, _ := json.Marshal(PairAttachMsg{Type: "pair_attach", Token: token})
	if err := alicePairConn.WriteMessage(websocket.TextMessage, attachData); err != nil {
		t.Fatal(err)
	}

	// Race the read against a short delay in a goroutine — if "paired" arrives
	// before Bob even joins, the server is not holding the attach correctly.
	// Note: we must NOT use gorilla read-deadline timeouts on alicePairConn here
	// because gorilla connections don't recover cleanly after a deadline timeout.
	// Instead we use a select on a channel.
	earlyPaired := make(chan struct{}, 1)
	go func() {
		// A very short sleep, then signal; if paired arrives before this fires
		// the server is not blocking.
		time.Sleep(50 * time.Millisecond)
		close(earlyPaired)
	}()
	pairedCh := make(chan error, 1)
	go func() {
		alicePairConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, data, err := alicePairConn.ReadMessage()
		alicePairConn.SetReadDeadline(time.Time{})
		if err != nil {
			pairedCh <- err
			return
		}
		var msg map[string]any
		json.Unmarshal(data, &msg)
		if msg["type"] != "paired" {
			pairedCh <- fmt.Errorf("expected paired, got %v", msg["type"])
			return
		}
		pairedCh <- nil
	}()

	// earlyPaired fires after 50 ms — by then "paired" must NOT have arrived yet.
	select {
	case <-earlyPaired:
		// good: still blocked
	case err := <-pairedCh:
		t.Fatalf("server sent paired before Bob joined: err=%v", err)
	}

	// Bob joins and attaches.
	bob.sendJSON(map[string]any{"type": "pair_join", "token": token})
	alice.readMsgAs("pair_ready")
	bob.readMsgAs("pair_ready")

	bobPair := env.dialPair(token)
	bobPair.expectPaired(5 * time.Second)

	// Now Alice's goroutine should unblock and receive paired.
	if err := <-pairedCh; err != nil {
		t.Fatal("alice did not receive paired after Bob joined:", err)
	}
}

func TestPairing_WrongToken(t *testing.T) {
	env := newTestEnv(t)

	conn, _, err := websocket.DefaultDialer.Dial(env.pairURL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	data, _ := json.Marshal(PairAttachMsg{Type: "pair_attach", Token: "doesnotexist"})
	conn.WriteMessage(websocket.TextMessage, data)

	// Server should close the connection.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected connection to be rejected, but read succeeded")
	}
}

func TestPairing_WrongFirstFrame(t *testing.T) {
	env := newTestEnv(t)

	conn, _, err := websocket.DefaultDialer.Dial(env.pairURL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	// Send the wrong message type.
	data, _ := json.Marshal(map[string]any{"type": "watch_tags", "tags": []string{}})
	conn.WriteMessage(websocket.TextMessage, data)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected connection to be rejected after wrong first frame")
	}
}

func TestPairing_Replay(t *testing.T) {
	// After both peers have attached, a third attach attempt must be rejected.
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	token := "11223344" + fmt.Sprintf("%056x", 0)

	doHandshake(t, alice, bob, token)
	alicePair := env.dialPair(token)
	bobPair := env.dialPair(token)
	alicePair.expectPaired(5 * time.Second)
	bobPair.expectPaired(5 * time.Second)

	// Third attacher — must be rejected.
	thirdConn, _, err := websocket.DefaultDialer.Dial(env.pairURL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { thirdConn.Close() })

	data, _ := json.Marshal(PairAttachMsg{Type: "pair_attach", Token: token})
	thirdConn.WriteMessage(websocket.TextMessage, data)

	thirdConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = thirdConn.ReadMessage()
	if err == nil {
		t.Fatal("expected third attacher to be rejected")
	}
}

func TestPairing_TTLExpiry(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	token := "ttltest0" + fmt.Sprintf("%056x", 0)

	alice.sendJSON(map[string]any{"type": "pair_offer", "token": token})
	alice.readMsgAs("pair_pending")

	// Wind back CreatedAt to make the session appear expired.
	env.relay.pairs.mu.Lock()
	sess := env.relay.pairs.sessions[token]
	sess.CreatedAt = time.Now().Add(-(pairSessionTTL + time.Second))
	env.relay.pairs.mu.Unlock()

	env.relay.pairs.cleanupExpired()

	// Alice should receive pair_closed on the main WS.
	msg := alice.readMsgAs("pair_closed")
	reason, _ := msg["reason"].(string)
	if reason != "ttl_expired" {
		t.Fatalf("expected reason=ttl_expired, got %q", reason)
	}

	// Session should be gone.
	env.relay.pairs.mu.Lock()
	_, exists := env.relay.pairs.sessions[token]
	env.relay.pairs.mu.Unlock()
	if exists {
		t.Fatal("session still in registry after TTL expiry")
	}
}

func TestPairing_DuplicateOffer(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	token := "dupetest" + fmt.Sprintf("%056x", 0)

	alice.sendJSON(map[string]any{"type": "pair_offer", "token": token})
	alice.readMsgAs("pair_pending")

	// Second offer with same token must fail.
	alice.sendJSON(map[string]any{"type": "pair_offer", "token": token})
	errMsg := alice.readMsgAs("error")
	if errMsg["message"] == "" {
		t.Fatal("expected error message for duplicate token")
	}
}

func TestPairing_MainWSDisconnect_CancelsSession(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	token := "disctest" + fmt.Sprintf("%056x", 0)

	alice.sendJSON(map[string]any{"type": "pair_offer", "token": token})
	alice.readMsgAs("pair_pending")

	bob.sendJSON(map[string]any{"type": "pair_join", "token": token})
	alice.readMsgAs("pair_ready")
	bob.readMsgAs("pair_ready")

	// Alice closes the main WS before opening the pair WS.
	alice.conn.Close()

	// Bob should receive pair_closed on the main WS.
	msg := bob.readMsgAs("pair_closed")
	reason, _ := msg["reason"].(string)
	if reason != "peer_gone" {
		t.Fatalf("expected reason=peer_gone, got %q", reason)
	}
}

func TestPairing_ByteCap(t *testing.T) {
	env := newTestEnv(t)
	// Set a very small session byte cap so we can trigger it in the test.
	env.relay.pairs.testSessionByteCap = 100

	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	token := "bytecap0" + fmt.Sprintf("%056x", 0)

	doHandshake(t, alice, bob, token)
	alicePair := env.dialPair(token)
	bobPair := env.dialPair(token)
	alicePair.expectPaired(5 * time.Second)
	bobPair.expectPaired(5 * time.Second)

	// Send enough data to exceed the 100-byte cap.
	alicePair.writeBinary(make([]byte, 101))

	// Both pair connections must close.
	alicePair.expectClose(5 * time.Second)

	// Both main-WS clients should receive pair_closed{reason:"byte_cap"}.
	aliceMsg, _ := alice.readMsg(5 * time.Second)
	if aliceMsg["type"] != "pair_closed" || aliceMsg["reason"] != "byte_cap" {
		t.Fatalf("alice: expected pair_closed/byte_cap, got %v", aliceMsg)
	}
	bobMsg, _ := bob.readMsg(5 * time.Second)
	if bobMsg["type"] != "pair_closed" || bobMsg["reason"] != "byte_cap" {
		t.Fatalf("bob: expected pair_closed/byte_cap, got %v", bobMsg)
	}

	// Metric should be incremented.
	if v := env.relay.pairs.metricByteCaps.Load(); v != 1 {
		t.Fatalf("pair_byte_cap_closes_total: want 1, got %d", v)
	}
}

func TestPairing_Metrics(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect("did:plc:alice")
	bob := env.connect("did:plc:bob")
	token := "metrics0" + fmt.Sprintf("%056x", 0)

	doHandshake(t, alice, bob, token)
	alicePair := env.dialPair(token)
	bobPair := env.dialPair(token)
	alicePair.expectPaired(5 * time.Second)
	bobPair.expectPaired(5 * time.Second)

	if v := env.relay.pairs.metricTotal.Load(); v != 1 {
		t.Fatalf("pair_sessions_total: want 1, got %d", v)
	}
	if v := env.relay.pairs.metricOpen.Load(); v != 1 {
		t.Fatalf("pair_sessions_open: want 1, got %d", v)
	}

	// Close session and verify metrics update.
	alicePair.conn.Close()
	time.Sleep(100 * time.Millisecond) // let goroutines settle
	if v := env.relay.pairs.metricOpen.Load(); v != 0 {
		t.Fatalf("pair_sessions_open after close: want 0, got %d", v)
	}
}

func TestPairing_MetricsEndpoint(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var metrics map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"pair_sessions_open",
		"pair_sessions_total",
		"pair_bytes_total",
		"pair_timeouts_total",
		"pair_byte_cap_closes_total",
	} {
		if _, ok := metrics[key]; !ok {
			t.Errorf("metrics missing key %q", key)
		}
	}
}

func TestPairing_JoinUnknownToken(t *testing.T) {
	env := newTestEnv(t)
	bob := env.connect("did:plc:bob")

	bob.sendJSON(map[string]any{"type": "pair_join", "token": "doesnotexist"})
	errMsg := bob.readMsgAs("error")
	if errMsg["message"] == "" {
		t.Fatal("expected error for unknown token")
	}
}

func TestPairing_PairURLFormat(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"wss://relay.example.com/ws", "wss://relay.example.com/pair"},
		{"ws://localhost:8080/ws", "ws://localhost:8080/pair"},
		{"wss://relay.example.com", "wss://relay.example.com/pair"},
	}
	for _, tc := range cases {
		got := pairWSURL(tc.in)
		if got != tc.want {
			t.Errorf("pairWSURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
