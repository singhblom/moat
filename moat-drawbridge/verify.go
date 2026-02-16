package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// PDSVerifier verifies that a claimed event exists on the sender's PDS.
type PDSVerifier interface {
	Verify(ctx context.Context, did, rkey, expectedTag string) error
}

// PDSVerifierImpl is the real PDS verification implementation.
type PDSVerifierImpl struct {
	client   *http.Client
	resolver DIDResolver
}

// NewPDSVerifier creates a new PDS verifier.
func NewPDSVerifier(resolver DIDResolver) *PDSVerifierImpl {
	return &PDSVerifierImpl{
		client:   &http.Client{Timeout: 10 * time.Second},
		resolver: resolver,
	}
}

func (v *PDSVerifierImpl) Verify(ctx context.Context, did, rkey, expectedTag string) error {
	// Resolve DID to get PDS endpoint
	doc, err := v.resolver.Resolve(ctx, did)
	if err != nil {
		return fmt.Errorf("DID resolution failed: %w", err)
	}

	pdsURL, err := doc.GetPDSEndpoint()
	if err != nil {
		return err
	}

	// Fetch the record
	reqURL := fmt.Sprintf("%s/xrpc/com.atproto.repo.getRecord?repo=%s&collection=%s&rkey=%s",
		pdsURL,
		url.QueryEscape(did),
		url.QueryEscape("social.moat.event"),
		url.QueryEscape(rkey),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("PDS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("record not found on PDS")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PDS returned status %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		Value struct {
			Tag json.RawMessage `json:"tag"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse PDS response: %w", err)
	}

	// ATProto encodes bytes as {"$bytes": "<base64>"}
	recordTag, err := decodeBytesField(result.Value.Tag)
	if err != nil {
		return fmt.Errorf("failed to decode tag field: %w", err)
	}

	recordTagHex := hex.EncodeToString(recordTag)
	if recordTagHex != expectedTag {
		return fmt.Errorf("tag mismatch: record has %s, claimed %s", recordTagHex, expectedTag)
	}

	return nil
}

// decodeBytesField decodes an ATProto bytes field: {"$bytes": "<base64>"}
func decodeBytesField(raw json.RawMessage) ([]byte, error) {
	var bytesObj struct {
		Bytes string `json:"$bytes"`
	}
	if err := json.Unmarshal(raw, &bytesObj); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(bytesObj.Bytes)
}

// RateLimiter tracks per-DID verification failures and applies soft rate limits.
type RateLimiter struct {
	mu       sync.Mutex
	failures map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	count      int
	limitUntil time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		failures: make(map[string]*rateLimitEntry),
	}
}

// RecordFailure records a verification failure for a DID.
// After 3 failures, the DID is rate-limited for 1 minute.
func (rl *RateLimiter) RecordFailure(did string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.failures[did]
	if !ok {
		entry = &rateLimitEntry{}
		rl.failures[did] = entry
	}

	entry.count++
	if entry.count >= 3 {
		entry.limitUntil = time.Now().Add(1 * time.Minute)
		entry.count = 0
	}
}

// IsLimited returns true if the DID is currently rate-limited.
func (rl *RateLimiter) IsLimited(did string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.failures[did]
	if !ok {
		return false
	}

	if time.Now().After(entry.limitUntil) {
		return false
	}

	return true
}
