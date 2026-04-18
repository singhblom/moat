package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	pairSessionTTL  = 5 * time.Minute
	pairSendBufSize = 64
)

const (
	maxPairFrameSize       int64 = 1 << 20       // 1 MiB per frame
	maxPairBytesPerSession int64 = 256 << 20      // 256 MiB per session
	maxPairBytesPerSecond  int64 = 8 << 20        // 8 MiB/s per connection
)

var (
	errDuplicateToken  = errors.New("token already registered")
	errTokenNotFound   = errors.New("token not found or expired")
	errAlreadyJoined   = errors.New("session already has a joiner")
	errAlreadyAttached = errors.New("session already fully attached")
)

// PairConn is the pair-WS side of a pairing session.
type PairConn struct {
	conn *websocket.Conn
	send chan []byte
	rate rateBucket
}

// rateBucket is a simple per-second token bucket for rate limiting.
type rateBucket struct {
	mu          sync.Mutex
	windowStart time.Time
	windowBytes int64
}

func (rb *rateBucket) allow(n, limitBPS int64) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	now := time.Now()
	if now.Sub(rb.windowStart) > time.Second {
		rb.windowStart = now
		rb.windowBytes = 0
	}
	if rb.windowBytes+n > limitBPS {
		return false
	}
	rb.windowBytes += n
	return true
}

// PairSession holds the state of one pairing rendezvous.
type PairSession struct {
	Token     string
	CreatedAt time.Time
	Offerer   *Client // main-WS client that sent pair_offer
	Joiner    *Client // main-WS client that sent pair_join; nil until joined

	mu          sync.Mutex
	A           *PairConn // first pair-WS attacher
	B           *PairConn // second pair-WS attacher
	attachCount int       // 0, 1, or 2; protected by mu
	peerForA    chan *PairConn // buffered(1); B sends itself; nil signals termination

	BytesAB atomic.Int64 // bytes forwarded A→B
	BytesBA atomic.Int64 // bytes forwarded B→A

	closed atomic.Bool
}

// PairRegistry manages active pairing sessions keyed by token.
type PairRegistry struct {
	mu       sync.Mutex
	sessions map[string]*PairSession

	// Override limits for testing (zero means use package defaults).
	testSessionByteCap int64
	testConnBPS        int64

	// Metrics — updated atomically.
	metricOpen     atomic.Int64
	metricTotal    atomic.Int64
	metricBytes    atomic.Int64
	metricTimeouts atomic.Int64
	metricByteCaps atomic.Int64
}

func newPairRegistry() *PairRegistry {
	return &PairRegistry{sessions: make(map[string]*PairSession)}
}

func (pr *PairRegistry) effectiveSessionByteCap() int64 {
	if pr.testSessionByteCap > 0 {
		return pr.testSessionByteCap
	}
	return maxPairBytesPerSession
}

func (pr *PairRegistry) effectiveConnBPS() int64 {
	if pr.testConnBPS > 0 {
		return pr.testConnBPS
	}
	return maxPairBytesPerSecond
}

// Offer registers a new pairing session for the given token and offerer.
func (pr *PairRegistry) Offer(c *Client, token string) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if _, exists := pr.sessions[token]; exists {
		return errDuplicateToken
	}
	pr.sessions[token] = &PairSession{
		Token:     token,
		CreatedAt: time.Now(),
		Offerer:   c,
		peerForA:  make(chan *PairConn, 1),
	}
	pr.metricOpen.Add(1)
	pr.metricTotal.Add(1)
	return nil
}

// Join records the joining client for the session identified by token.
func (pr *PairRegistry) Join(c *Client, token string) (*PairSession, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	sess, ok := pr.sessions[token]
	if !ok {
		return nil, errTokenNotFound
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Joiner != nil {
		return nil, errAlreadyJoined
	}
	sess.Joiner = c
	return sess, nil
}

// Attach binds a pair-WS connection to a session.
//
// The first caller (n==1) stores itself as A, then blocks until B attaches or
// the session TTL expires. The second caller (n==2) stores itself as B, signals
// A via peerForA, and returns A as its peer. Both return (peer, sess, nil).
func (pr *PairRegistry) Attach(pc *PairConn, token string) (*PairConn, *PairSession, error) {
	pr.mu.Lock()
	sess, ok := pr.sessions[token]
	if !ok {
		pr.mu.Unlock()
		return nil, nil, errTokenNotFound
	}

	sess.mu.Lock()
	sess.attachCount++
	n := sess.attachCount
	if n > 2 {
		sess.attachCount--
		sess.mu.Unlock()
		pr.mu.Unlock()
		return nil, nil, errAlreadyAttached
	}

	if n == 1 {
		sess.A = pc
		peerCh := sess.peerForA
		remaining := pairSessionTTL - time.Since(sess.CreatedAt)
		sess.mu.Unlock()
		pr.mu.Unlock()

		select {
		case peer, ok := <-peerCh:
			if !ok || peer == nil {
				return nil, nil, errors.New("pairing session terminated")
			}
			return peer, sess, nil
		case <-time.After(remaining):
			pr.metricTimeouts.Add(1)
			return nil, nil, errors.New("timeout waiting for peer to attach")
		}
	}

	// n == 2: second attacher — unblock A and return immediately.
	sess.B = pc
	peerA := sess.A
	peerCh := sess.peerForA
	sess.mu.Unlock()
	pr.mu.Unlock()

	peerCh <- pc // buffered(1), will not block
	return peerA, sess, nil
}

// terminateSession removes a session from the registry by token and terminates it.
// Safe to call multiple times; only the first call has effect.
func (pr *PairRegistry) terminateSession(token, reason string) {
	pr.mu.Lock()
	sess, ok := pr.sessions[token]
	if !ok {
		pr.mu.Unlock()
		return
	}
	delete(pr.sessions, token)
	pr.mu.Unlock()
	pr.terminate(sess, reason)
}

// onMainWSDisconnect cancels pending pairing sessions where c is the offerer or
// joiner and the pair WS has not yet been established.
func (pr *PairRegistry) onMainWSDisconnect(c *Client) {
	pr.mu.Lock()
	var victims []*PairSession
	for token, sess := range pr.sessions {
		if sess.Offerer == c || sess.Joiner == c {
			delete(pr.sessions, token)
			victims = append(victims, sess)
		}
	}
	pr.mu.Unlock()
	for _, sess := range victims {
		pr.terminate(sess, "peer_gone")
	}
}

// cleanupExpired removes sessions that have exceeded pairSessionTTL.
func (pr *PairRegistry) cleanupExpired() {
	pr.mu.Lock()
	var expired []*PairSession
	now := time.Now()
	for token, sess := range pr.sessions {
		if now.Sub(sess.CreatedAt) > pairSessionTTL {
			delete(pr.sessions, token)
			expired = append(expired, sess)
		}
	}
	pr.mu.Unlock()
	for _, sess := range expired {
		pr.metricTimeouts.Add(1)
		pr.terminate(sess, "ttl_expired")
	}
}

func (pr *PairRegistry) terminate(sess *PairSession, reason string) {
	if !sess.closed.CompareAndSwap(false, true) {
		return
	}
	pr.metricOpen.Add(-1)
	pr.metricBytes.Add(sess.BytesAB.Load() + sess.BytesBA.Load())

	// Signal any goroutine blocked in Attach waiting for a peer.
	sess.mu.Lock()
	n := sess.attachCount
	peerCh := sess.peerForA
	a, b := sess.A, sess.B
	sess.mu.Unlock()

	if n < 2 {
		select {
		case peerCh <- nil: // nil signals termination to the waiting goroutine
		default:
		}
	}

	// Notify main-WS clients.
	msg := PairClosedMsg{Type: "pair_closed", Reason: reason}
	if sess.Offerer != nil {
		sess.Offerer.sendMsg(msg)
	}
	if sess.Joiner != nil {
		sess.Joiner.sendMsg(msg)
	}

	// Stop pair-WS write pumps and close underlying connections.
	if a != nil {
		closePairSend(a.send)
		a.conn.Close()
	}
	if b != nil {
		closePairSend(b.send)
		b.conn.Close()
	}
}

// closePairSend closes ch exactly once, ignoring any double-close panic.
func closePairSend(ch chan []byte) {
	defer func() { recover() }()
	close(ch)
}

// runPairWritePump drains pc.send and writes each payload as a binary WebSocket
// frame. Exits when the send channel is closed.
func runPairWritePump(pc *PairConn) {
	defer pc.conn.Close()
	for data := range pc.send {
		pc.conn.SetWriteDeadline(time.Now().Add(writeWait))
		if err := pc.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			return
		}
	}
}

// runPairForwarder reads binary frames from pc and forwards them to peerSend.
// direction: 0 = A→B (updates sess.BytesAB), 1 = B→A (updates sess.BytesBA).
// onByteCap is called when the per-connection rate limit or per-session byte cap
// is exceeded; the caller is then responsible for terminating the session.
func runPairForwarder(pc *PairConn, peerSend chan []byte, sess *PairSession, reg *PairRegistry, direction int, onByteCap func()) {
	defer pc.conn.Close()
	pc.conn.SetReadLimit(maxPairFrameSize)

	for {
		mt, data, err := pc.conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			continue // ignore non-binary frames
		}
		n := int64(len(data))

		// Per-connection rate limit.
		if !pc.rate.allow(n, reg.effectiveConnBPS()) {
			onByteCap()
			return
		}

		// Per-session byte cap.
		var totalSession int64
		if direction == 0 {
			totalSession = sess.BytesAB.Add(n) + sess.BytesBA.Load()
		} else {
			totalSession = sess.BytesBA.Add(n) + sess.BytesAB.Load()
		}
		if totalSession > reg.effectiveSessionByteCap() {
			onByteCap()
			return
		}

		select {
		case peerSend <- data:
		default:
			// Peer send buffer full — drop the frame.
		}
	}
}
