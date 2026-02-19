package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	didCacheTTL     = 1 * time.Hour
	timestampWindow = 60 // seconds
)

// DIDResolver resolves a DID to its document.
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*DIDDocument, error)
}

// DIDDocument represents an ATProto DID document.
type DIDDocument struct {
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Service            []Service            `json:"service"`
}

// VerificationMethod is a key in a DID document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// Service is a service endpoint in a DID document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// GetPDSEndpoint extracts the PDS service endpoint from a DID document.
func (d *DIDDocument) GetPDSEndpoint() (string, error) {
	for _, svc := range d.Service {
		if svc.Type == "AtprotoPersonalDataServer" {
			return svc.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("no PDS endpoint in DID document")
}

// DIDCache caches resolved DID documents.
type DIDCache struct {
	mu      sync.RWMutex
	entries map[string]*didCacheEntry
}

type didCacheEntry struct {
	doc       *DIDDocument
	fetchedAt time.Time
}

// NewDIDCache creates a new DID cache.
func NewDIDCache() *DIDCache {
	return &DIDCache{
		entries: make(map[string]*didCacheEntry),
	}
}

// Get returns a cached DID document if it exists and is not expired.
func (c *DIDCache) Get(did string) (*DIDDocument, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[did]
	if !ok || time.Since(entry.fetchedAt) > didCacheTTL {
		return nil, false
	}
	return entry.doc, true
}

// Put stores a DID document in the cache.
func (c *DIDCache) Put(did string, doc *DIDDocument) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[did] = &didCacheEntry{doc: doc, fetchedAt: time.Now()}
}

// PLCResolver resolves did:plc DIDs via the PLC directory.
type PLCResolver struct {
	client  *http.Client
	baseURL string // default: https://plc.directory
	cache   *DIDCache
}

// NewPLCResolver creates a new PLC directory resolver.
func NewPLCResolver(cache *DIDCache) *PLCResolver {
	return &PLCResolver{
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: "https://plc.directory",
		cache:   cache,
	}
}

func (r *PLCResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:plc:") {
		return nil, fmt.Errorf("unsupported DID method: %s", did)
	}

	if doc, ok := r.cache.Get(did); ok {
		return doc, nil
	}

	url := r.baseURL + "/" + did
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PLC directory request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PLC directory returned %d for %s", resp.StatusCode, did)
	}

	var doc DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode DID document: %w", err)
	}

	r.cache.Put(did, &doc)
	return &doc, nil
}

// authenticate verifies a client's challenge response.
// The client provides its Ed25519 public key in the message. We verify the
// signature locally against that key, then asynchronously verify that the key
// exists in one of the DID's key package records on their PDS.
func (r *Relay) authenticate(c *Client, resp *ChallengeResponseMsg) error {
	// Check timestamp window
	now := time.Now().Unix()
	if abs(now-resp.Timestamp) > timestampWindow {
		return fmt.Errorf("timestamp outside acceptable window")
	}

	// Decode the provided public key
	if resp.PublicKey == "" {
		return fmt.Errorf("public_key is required")
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public_key encoding: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public_key length: expected %d, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Verify challenge signature against the provided public key
	if err := verifyChallenge(pubKey, c.nonce, c.relayURL, resp.Timestamp, sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Authentication successful (signature is valid)
	r.registerDID(c, resp.DID)

	// Async verify that the public key exists in the DID's key package records
	go r.asyncVerifyKeyPackage(resp.DID, pubKeyBytes)

	return nil
}

// verifyChallenge verifies an Ed25519 challenge signature.
// The signed message is: nonce\nrelay_url\ntimestamp\n
func verifyChallenge(pubKey ed25519.PublicKey, nonce, relayURL string, timestamp int64, signature []byte) error {
	message := []byte(nonce + "\n" + relayURL + "\n" + strconv.FormatInt(timestamp, 10) + "\n")
	if !ed25519.Verify(pubKey, message, signature) {
		return fmt.Errorf("Ed25519 signature invalid")
	}
	return nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
