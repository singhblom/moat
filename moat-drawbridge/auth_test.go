package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

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

// Helper to create base64-encoded Ed25519 signature for tests
func signChallengeEd25519(priv ed25519.PrivateKey, nonce, relayURL string, timestamp int64) string {
	message := []byte(nonce + "\n" + relayURL + "\n" + strconv.FormatInt(timestamp, 10) + "\n")
	sig := ed25519.Sign(priv, message)
	return base64.StdEncoding.EncodeToString(sig)
}

// Helper to base64-encode an Ed25519 public key for tests
func encodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
