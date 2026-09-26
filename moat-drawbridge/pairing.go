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

	// sendLock orders enqueue against closeSend, so a frame is never sent on a
	// closed channel.
	sendLock   sync.Mutex
	sendClosed bool
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

	pairLock    sync.Mutex
	A           *PairConn // first pair-WS attacher
	B           *PairConn // second pair-WS attacher
	attachCount int       // 0, 1, or 2; protected by pairLock
	peerForA    chan *PairConn // buffered(1); B sends itself; nil signals termination

	BytesAB atomic.Int64 // bytes forwarded A→B
	BytesBA atomic.Int64 // bytes forwarded B→A

	closed atomic.Bool
}

// PairRegistry manages active pairing sessions keyed by token.
type PairRegistry struct {
	pairLock sync.Mutex
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
	pr.pairLock.Lock()
	defer pr.pairLock.Unlock()
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
	pr.pairLock.Lock()
	defer pr.pairLock.Unlock()
	sess, ok := pr.sessions[token]
	if !ok {
		return nil, errTokenNotFound
	}
	sess.pairLock.Lock()
	defer sess.pairLock.Unlock()
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
	pr.pairLock.Lock()
	sess, ok := pr.sessions[token]
	if !ok {
		pr.pairLock.Unlock()
		return nil, nil, errTokenNotFound
	}

	sess.pairLock.Lock()
	sess.attachCount++
	n := sess.attachCount
	if n > 2 {
		sess.attachCount--
		sess.pairLock.Unlock()
		pr.pairLock.Unlock()
		return nil, nil, errAlreadyAttached
	}

	if n == 1 {
		sess.A = pc
		peerCh := sess.peerForA
		remaining := pairSessionTTL - time.Since(sess.CreatedAt)
		sess.pairLock.Unlock()
		pr.pairLock.Unlock()

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
	sess.pairLock.Unlock()
	pr.pairLock.Unlock()

	peerCh <- pc // buffered(1), will not block
	return peerA, sess, nil
}

// terminateSession removes a session from the registry by token and terminates
// it. Safe to call multiple times; only the first call has effect. See
// terminate for drain.
func (pr *PairRegistry) terminateSession(token, reason string, drain bool) {
	pr.pairLock.Lock()
	sess, ok := pr.sessions[token]
	if !ok {
		pr.pairLock.Unlock()
		return
	}
	delete(pr.sessions, token)
	pr.pairLock.Unlock()
	pr.terminate(sess, reason, drain)
}

// onMainWSDisconnect cancels pending pairing sessions where c is the offerer or
// joiner and the pair WS has not yet been established.
//
// Skips fully-attached sessions (attachCount == 2): bulk transfer runs on
// the separate /pair socket precisely so a main-WS blip can't abort a
// minutes-long history sync. A peer that really left still gets cleaned up
// when its /pair socket closes (servePairWS → terminateSession), with
// cleanupExpired as the TTL backstop.
func (pr *PairRegistry) onMainWSDisconnect(c *Client) {
	pr.pairLock.Lock()
	var victims []*PairSession
	for token, sess := range pr.sessions {
		if sess.Offerer != c && sess.Joiner != c {
			continue
		}
		sess.pairLock.Lock()
		fullyAttached := sess.attachCount == 2
		sess.pairLock.Unlock()
		if fullyAttached {
			continue
		}
		delete(pr.sessions, token)
		victims = append(victims, sess)
	}
	pr.pairLock.Unlock()
	for _, sess := range victims {
		pr.terminate(sess, "peer_gone", false)
	}
}

// cleanupExpired removes sessions that have exceeded pairSessionTTL.
func (pr *PairRegistry) cleanupExpired() {
	pr.pairLock.Lock()
	var expired []*PairSession
	now := time.Now()
	for token, sess := range pr.sessions {
		if now.Sub(sess.CreatedAt) > pairSessionTTL {
			delete(pr.sessions, token)
			expired = append(expired, sess)
		}
	}
	pr.pairLock.Unlock()
	for _, sess := range expired {
		pr.metricTimeouts.Add(1)
		pr.terminate(sess, "ttl_expired", false)
	}
}

// terminate closes a session exactly once. With drain, each pair socket is
// closed by its write pump after the frames already queued for it are written
// — the last frame before a close is often the one that confirms a transfer;
// without, sockets are closed at once.
func (pr *PairRegistry) terminate(sess *PairSession, reason string, drain bool) {
	if !sess.closed.CompareAndSwap(false, true) {
		return
	}
	pr.metricOpen.Add(-1)
	pr.metricBytes.Add(sess.BytesAB.Load() + sess.BytesBA.Load())

	// Signal any goroutine blocked in Attach waiting for a peer.
	sess.pairLock.Lock()
	n := sess.attachCount
	peerCh := sess.peerForA
	a, b := sess.A, sess.B
	sess.pairLock.Unlock()

	if n < 2 {
		select {
		case peerCh <- nil: // nil signals termination to the waiting goroutine
		default:
		}
	}

	// Notify main-WS clients.
	msg := PairClosedMsg{Type: "pair_closed", SessionToken: sess.Token, Reason: reason}
	if sess.Offerer != nil {
		sess.Offerer.sendMsg(msg)
	}
	if sess.Joiner != nil {
		sess.Joiner.sendMsg(msg)
	}

	// Stop pair-WS write pumps and close underlying connections.
	for _, pc := range []*PairConn{a, b} {
		if pc == nil {
			continue
		}
		pc.closeSend()
		if !drain {
			pc.conn.Close()
		}
	}
}

// enqueue queues data for the pair socket, dropping it if the buffer is full
// or the session has ended.
func (pc *PairConn) enqueue(data []byte) {
	pc.sendLock.Lock()
	defer pc.sendLock.Unlock()
	if pc.sendClosed {
		return
	}
	select {
	case pc.send <- data:
	default:
	}
}

// closeSend ends the outbound queue; the write pump drains it and exits.
func (pc *PairConn) closeSend() {
	pc.sendLock.Lock()
	defer pc.sendLock.Unlock()
	if !pc.sendClosed {
		pc.sendClosed = true
		close(pc.send)
	}
}

// runPairWritePump drains pc.send and writes each payload as a binary WebSocket
// frame. When the send channel is closed it ends the socket with a normal close.
func runPairWritePump(pc *PairConn) {
	defer pc.conn.Close()
	for data := range pc.send {
		pc.conn.SetWriteDeadline(time.Now().Add(writeWait))
		if err := pc.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			return
		}
	}
	pc.conn.SetWriteDeadline(time.Now().Add(writeWait))
	pc.conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// runPairForwarder reads binary frames from pc and forwards them to peer.
// direction: 0 = A→B (updates sess.BytesAB), 1 = B→A (updates sess.BytesBA).
// onByteCap is called when the per-connection rate limit or per-session byte cap
// is exceeded; the caller is then responsible for terminating the session.
func runPairForwarder(pc *PairConn, peer *PairConn, sess *PairSession, reg *PairRegistry, direction int, onByteCap func()) {
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

		peer.enqueue(data)
	}
}
