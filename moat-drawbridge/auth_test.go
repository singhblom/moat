package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strconv"
	"testing"
	"time"
)

func TestDecodeMultibaseKey_Ed25519(t *testing.T) {
	// Generate a keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Encode as multibase (z-prefix base58btc) with multicodec prefix 0xed01
	raw := append([]byte{0xed, 0x01}, pub...)
	encoded := "z" + encodeBase58(raw)

	key, err := decodeMultibaseKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", key)
	}

	if !edKey.Equal(pub) {
		t.Fatal("decoded key does not match original")
	}
}

func TestDecodeMultibaseKey_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Compressed SEC1 format
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	raw := append([]byte{0x80, 0x24}, compressed...)
	encoded := "z" + encodeBase58(raw)

	key, err := decodeMultibaseKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	if ecKey.X.Cmp(priv.PublicKey.X) != 0 || ecKey.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("decoded key does not match original")
	}
}

func TestVerifyChallenge_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nonce := "abc123"
	relayURL := "wss://relay.example.com"
	timestamp := time.Now().Unix()

	message := []byte(nonce + "\n" + relayURL + "\n" + strconv.FormatInt(timestamp, 10) + "\n")
	sig := ed25519.Sign(priv, message)

	if err := verifyChallenge(pub, nonce, relayURL, timestamp, sig); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChallenge_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nonce := "def456"
	relayURL := "wss://relay.example.com"
	timestamp := time.Now().Unix()

	message := []byte(nonce + "\n" + relayURL + "\n" + strconv.FormatInt(timestamp, 10) + "\n")
	hash := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyChallenge(&priv.PublicKey, nonce, relayURL, timestamp, sig); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChallenge_WrongSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	err = verifyChallenge(pub, "nonce", "wss://relay", time.Now().Unix(), []byte("badsig"))
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestBase58RoundTrip(t *testing.T) {
	original := []byte{0xed, 0x01, 0x00, 0xff, 0x42, 0x7a}
	encoded := encodeBase58(original)
	decoded, err := decodeBase58(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("byte %d mismatch: got 0x%02x, want 0x%02x", i, decoded[i], original[i])
		}
	}
}

func TestBase58LeadingZeros(t *testing.T) {
	original := []byte{0x00, 0x00, 0x01}
	encoded := encodeBase58(original)
	decoded, err := decodeBase58(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("byte %d mismatch: got 0x%02x, want 0x%02x", i, decoded[i], original[i])
		}
	}
}

// encodeBase58 encodes bytes to base58btc. Used in tests only.
func encodeBase58(data []byte) string {
	// Count leading zeros
	var leadingZeros int
	for _, b := range data {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert to big int
	var n = new(big.Int).SetBytes(data)
	zero := new(big.Int)
	base := new(big.Int).SetInt64(58)
	mod := new(big.Int)

	var result []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Add leading '1's for zero bytes
	for i := 0; i < leadingZeros; i++ {
		result = append(result, '1')
	}

	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// Helper to create base64-encoded Ed25519 signature for tests
func signChallengeEd25519(priv ed25519.PrivateKey, nonce, relayURL string, timestamp int64) string {
	message := []byte(nonce + "\n" + relayURL + "\n" + strconv.FormatInt(timestamp, 10) + "\n")
	sig := ed25519.Sign(priv, message)
	return base64.StdEncoding.EncodeToString(sig)
}
