package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
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
func (r *Relay) authenticate(c *Client, resp *ChallengeResponseMsg) error {
	// Check timestamp window
	now := time.Now().Unix()
	if abs(now-resp.Timestamp) > timestampWindow {
		return fmt.Errorf("timestamp outside acceptable window")
	}

	// Resolve DID
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	doc, err := r.resolver.Resolve(ctx, resp.DID)
	if err != nil {
		return fmt.Errorf("DID resolution failed: %w", err)
	}

	// Extract signing key
	pubKey, err := extractSigningKey(doc)
	if err != nil {
		return fmt.Errorf("key extraction failed: %w", err)
	}

	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Verify challenge
	if err := verifyChallenge(pubKey, c.nonce, r.relayURL, resp.Timestamp, sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Authentication successful
	r.registerDID(c, resp.DID)
	return nil
}

// extractSigningKey extracts the signing public key from a DID document.
// Looks for the #atproto verification method first, then falls back to any Multikey method.
func extractSigningKey(doc *DIDDocument) (crypto.PublicKey, error) {
	var method *VerificationMethod

	// Look for the #atproto key first
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if vm.ID == doc.ID+"#atproto" || vm.ID == "#atproto" {
			method = vm
			break
		}
	}

	// Fallback to first Multikey
	if method == nil {
		for i := range doc.VerificationMethod {
			vm := &doc.VerificationMethod[i]
			if vm.Type == "Multikey" {
				method = vm
				break
			}
		}
	}

	if method == nil {
		return nil, fmt.Errorf("no suitable verification method found")
	}

	return decodeMultibaseKey(method.PublicKeyMultibase)
}

// decodeMultibaseKey decodes a multibase+multicodec-encoded public key.
func decodeMultibaseKey(encoded string) (crypto.PublicKey, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("empty multibase key")
	}

	// Only support 'z' prefix (base58btc)
	if encoded[0] != 'z' {
		return nil, fmt.Errorf("unsupported multibase prefix: %c", encoded[0])
	}

	raw, err := decodeBase58(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("base58 decode failed: %w", err)
	}

	if len(raw) < 2 {
		return nil, fmt.Errorf("multicodec key too short")
	}

	// Check multicodec prefix
	switch {
	case raw[0] == 0xed && raw[1] == 0x01:
		// Ed25519 public key
		keyBytes := raw[2:]
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key length: %d", len(keyBytes))
		}
		return ed25519.PublicKey(keyBytes), nil

	case raw[0] == 0x80 && raw[1] == 0x24:
		// P-256 compressed public key
		keyBytes := raw[2:]
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
		if x == nil {
			return nil, fmt.Errorf("invalid P-256 compressed key")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("unsupported multicodec prefix: 0x%02x%02x", raw[0], raw[1])
	}
}

// verifyChallenge verifies a challenge signature.
// The signed message is: nonce\nrelay_url\ntimestamp\n
func verifyChallenge(pubKey crypto.PublicKey, nonce, relayURL string, timestamp int64, signature []byte) error {
	message := []byte(nonce + "\n" + relayURL + "\n" + strconv.FormatInt(timestamp, 10) + "\n")

	switch key := pubKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, message, signature) {
			return fmt.Errorf("Ed25519 signature invalid")
		}
		return nil

	case *ecdsa.PublicKey:
		hash := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			return fmt.Errorf("P-256 signature invalid")
		}
		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

// Base58btc alphabet
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58 decodes a base58btc-encoded string.
func decodeBase58(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("empty base58 string")
	}

	// Build alphabet index
	var alphabetIndex [256]int
	for i := range alphabetIndex {
		alphabetIndex[i] = -1
	}
	for i, c := range base58Alphabet {
		alphabetIndex[c] = i
	}

	result := new(big.Int)
	base := big.NewInt(58)

	for _, c := range []byte(s) {
		val := alphabetIndex[c]
		if val == -1 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(val)))
	}

	// Convert to bytes
	resultBytes := result.Bytes()

	// Count leading zeros (1s in base58)
	var leadingZeros int
	for _, c := range []byte(s) {
		if c == '1' {
			leadingZeros++
		} else {
			break
		}
	}

	// Prepend leading zero bytes
	if leadingZeros > 0 {
		padding := make([]byte, leadingZeros)
		resultBytes = append(padding, resultBytes...)
	}

	return resultBytes, nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
