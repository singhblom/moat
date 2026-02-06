package main

import (
	"testing"
	"time"
)

func TestRateLimiter_NotLimitedInitially(t *testing.T) {
	rl := NewRateLimiter()
	if rl.IsLimited("did:plc:test") {
		t.Fatal("should not be limited initially")
	}
}

func TestRateLimiter_LimitedAfterFailures(t *testing.T) {
	rl := NewRateLimiter()

	rl.RecordFailure("did:plc:test")
	rl.RecordFailure("did:plc:test")
	if rl.IsLimited("did:plc:test") {
		t.Fatal("should not be limited after 2 failures")
	}

	rl.RecordFailure("did:plc:test")
	if !rl.IsLimited("did:plc:test") {
		t.Fatal("should be limited after 3 failures")
	}
}

func TestRateLimiter_LimitExpires(t *testing.T) {
	rl := NewRateLimiter()

	rl.RecordFailure("did:plc:test")
	rl.RecordFailure("did:plc:test")
	rl.RecordFailure("did:plc:test")

	// Manually expire the limit
	rl.mu.Lock()
	rl.failures["did:plc:test"].limitUntil = time.Now().Add(-1 * time.Second)
	rl.mu.Unlock()

	if rl.IsLimited("did:plc:test") {
		t.Fatal("should not be limited after expiry")
	}
}

func TestRateLimiter_IndependentDIDs(t *testing.T) {
	rl := NewRateLimiter()

	rl.RecordFailure("did:plc:a")
	rl.RecordFailure("did:plc:a")
	rl.RecordFailure("did:plc:a")

	if !rl.IsLimited("did:plc:a") {
		t.Fatal("a should be limited")
	}
	if rl.IsLimited("did:plc:b") {
		t.Fatal("b should not be limited")
	}
}
