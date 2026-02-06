package main

import "encoding/json"

// Envelope is used for initial deserialization to determine message type.
type Envelope struct {
	Type string          `json:"type"`
	Raw  json.RawMessage `json:"-"`
}

// Server -> Client messages

type ChallengeMsg struct {
	Type  string `json:"type"`  // "challenge"
	Nonce string `json:"nonce"` // random hex, 32 bytes
}

type AuthenticatedMsg struct {
	Type string `json:"type"` // "authenticated"
}

type ErrorMsg struct {
	Type    string `json:"type"`    // "error"
	Message string `json:"message"`
}

type NewEventMsg struct {
	Type string `json:"type"` // "new_event"
	Tag  string `json:"tag"`
	RKey string `json:"rkey"`
	DID  string `json:"did"`
}

// Client -> Server messages

type ChallengeResponseMsg struct {
	Type      string `json:"type"`      // "challenge_response"
	DID       string `json:"did"`
	Signature string `json:"signature"` // base64
	Timestamp int64  `json:"timestamp"` // unix seconds
}

type WatchTagsMsg struct {
	Type string   `json:"type"` // "watch_tags"
	Tags []string `json:"tags"`
}

type UpdateTagsMsg struct {
	Type   string   `json:"type"` // "update_tags"
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

type EventPostedMsg struct {
	Type string `json:"type"` // "event_posted"
	Tag  string `json:"tag"`
	RKey string `json:"rkey"`
}

type RegisterPushMsg struct {
	Type     string `json:"type"`     // "register_push"
	Platform string `json:"platform"` // "fcm" or "apns"
	Token    string `json:"token"`
}

// parseMessage deserializes a raw JSON message into the appropriate typed struct.
func parseMessage(data []byte) (string, any, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return "", nil, err
	}

	switch env.Type {
	case "challenge_response":
		var msg ChallengeResponseMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return env.Type, nil, err
		}
		return env.Type, &msg, nil
	case "watch_tags":
		var msg WatchTagsMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return env.Type, nil, err
		}
		return env.Type, &msg, nil
	case "update_tags":
		var msg UpdateTagsMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return env.Type, nil, err
		}
		return env.Type, &msg, nil
	case "event_posted":
		var msg EventPostedMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return env.Type, nil, err
		}
		return env.Type, &msg, nil
	case "register_push":
		var msg RegisterPushMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return env.Type, nil, err
		}
		return env.Type, &msg, nil
	default:
		return env.Type, nil, nil
	}
}
