package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecordingFCMSender_RecordsAndSnapshot(t *testing.T) {
	s := &RecordingFCMSender{}

	if err := s.Send(context.Background(), "tok-a", "tag1", "rkey1", "payload1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), "tok-b", "tag2", "rkey2", "payload2"); err != nil {
		t.Fatal(err)
	}

	snap := s.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 records, got %d", len(snap))
	}
	if snap[0].Token != "tok-a" || snap[0].Tag != "tag1" || snap[0].RKey != "rkey1" || snap[0].Payload != "payload1" {
		t.Errorf("record[0] mismatch: %+v", snap[0])
	}
	if snap[1].Token != "tok-b" {
		t.Errorf("record[1] token mismatch: %+v", snap[1])
	}

	// Snapshot must be a copy — mutations don't affect the sender.
	snap[0].Token = "mutated"
	snap2 := s.Snapshot()
	if snap2[0].Token == "mutated" {
		t.Error("snapshot is not a copy: mutation affected sender state")
	}
}

func TestRecordingFCMSender_Reset(t *testing.T) {
	s := &RecordingFCMSender{}
	s.Send(context.Background(), "tok", "tag", "rkey", "payload")

	s.Reset()
	if len(s.Snapshot()) != 0 {
		t.Fatal("expected empty snapshot after Reset")
	}

	// Can add more records after reset.
	s.Send(context.Background(), "tok2", "tag2", "rkey2", "payload2")
	if len(s.Snapshot()) != 1 {
		t.Fatal("expected 1 record after post-reset send")
	}
}

func TestRecordingFCMSender_HTTPRoutes(t *testing.T) {
	s := &RecordingFCMSender{}
	mux := http.NewServeMux()
	s.RegisterHTTPRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Initially empty.
	resp, err := http.Get(srv.URL + "/test/push-log")
	if err != nil {
		t.Fatal(err)
	}
	var records []RecordedPush
	json.NewDecoder(resp.Body).Decode(&records)
	resp.Body.Close()
	if len(records) != 0 {
		t.Fatalf("expected empty log, got %d records", len(records))
	}

	// Add a record via Send.
	s.Send(context.Background(), "tok-x", "tagX", "rkeyX", "pldX")

	resp, err = http.Get(srv.URL + "/test/push-log")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&records)
	resp.Body.Close()
	if len(records) != 1 || records[0].Token != "tok-x" {
		t.Fatalf("expected 1 record with token tok-x, got %+v", records)
	}

	// Reset via POST.
	resp, err = http.Post(srv.URL+"/test/push-log/reset", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 from reset, got %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/test/push-log")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&records)
	resp.Body.Close()
	if len(records) != 0 {
		t.Fatalf("expected empty log after reset, got %d records", len(records))
	}
}

func TestRecordingFCMSender_MethodNotAllowed(t *testing.T) {
	s := &RecordingFCMSender{}
	mux := http.NewServeMux()
	s.RegisterHTTPRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// POST to /test/push-log should be rejected.
	resp, err := http.Post(srv.URL+"/test/push-log", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /test/push-log, got %d", resp.StatusCode)
	}

	// GET to /test/push-log/reset should be rejected.
	resp, err = http.Get(srv.URL + "/test/push-log/reset")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET /test/push-log/reset, got %d", resp.StatusCode)
	}
}
