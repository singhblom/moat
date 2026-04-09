package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// RecordedPush captures a single FCM send call for test inspection.
type RecordedPush struct {
	Token     string    `json:"token"`
	Tag       string    `json:"tag"`
	RKey      string    `json:"rkey"`
	Payload   string    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// RecordingFCMSender captures every Send call into an in-memory slice.
// Exposes Snapshot/Reset for test assertions and HTTP routes for Beacon tests.
//
// WARNING: this is for integration testing only. Do not run with
// FCM_SENDER=recording in production — the HTTP routes expose push payloads
// without authentication.
type RecordingFCMSender struct {
	mu      sync.Mutex
	records []RecordedPush
}

func (r *RecordingFCMSender) Send(_ context.Context, token, tag, rkey, payload string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, RecordedPush{
		Token:     token,
		Tag:       tag,
		RKey:      rkey,
		Payload:   payload,
		Timestamp: time.Now(),
	})
	return nil
}

// Snapshot returns a copy of all recorded pushes.
func (r *RecordingFCMSender) Snapshot() []RecordedPush {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]RecordedPush, len(r.records))
	copy(cp, r.records)
	return cp
}

// Reset clears all recorded pushes.
func (r *RecordingFCMSender) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = r.records[:0]
}

// RegisterHTTPRoutes adds the test-only push-log endpoints to mux.
// Only called when the relay is running with a RecordingFCMSender.
//
//	GET  /test/push-log       — returns all recorded pushes as JSON
//	POST /test/push-log/reset — clears the log (204 No Content)
func (r *RecordingFCMSender) RegisterHTTPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/test/push-log", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.Snapshot())
	})
	mux.HandleFunc("/test/push-log/reset", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Reset()
		w.WriteHeader(http.StatusNoContent)
	})
}
