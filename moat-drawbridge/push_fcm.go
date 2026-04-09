package main

import (
	"context"
	"errors"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
)

// ErrTokenUnregistered is returned by FCMSender.Send when the device token has
// been invalidated by FCM or APNs. The relay should remove the push registration
// so the dead token is not retried on future events.
var ErrTokenUnregistered = errors.New("push token unregistered")

// FCMSender abstracts push notification delivery. Three implementations:
//   - NoopFCMSender     — used when FCM is not configured
//   - FirebaseFCMSender — real Firebase Admin SDK delivery
//   - RecordingFCMSender — captures sends for integration tests (never deploy)
type FCMSender interface {
	Send(ctx context.Context, token, tag, rkey, payload string) error
}

// NoopFCMSender discards all push requests silently. Used when FCM_SENDER=noop
// or when FCM_CREDENTIALS_FILE is not set.
type NoopFCMSender struct{}

func (n *NoopFCMSender) Send(_ context.Context, _, _, _, _ string) error {
	return nil
}

// FirebaseFCMSender delivers push notifications via the Firebase Admin SDK.
// A single sender handles both Android (FCM) and iOS (APNs via FCM HTTP v1 API)
// by uploading the APNs auth key to the Firebase project — no second SDK needed.
type FirebaseFCMSender struct {
	client *messaging.Client
}

// NewFirebaseFCMSender initialises a Firebase messaging client from a service
// account JSON credentials file.
func NewFirebaseFCMSender(credentialsFile string) (*FirebaseFCMSender, error) {
	app, err := firebase.NewApp(context.Background(), nil,
		option.WithCredentialsFile(credentialsFile))
	if err != nil {
		return nil, err
	}
	client, err := app.Messaging(context.Background())
	if err != nil {
		return nil, err
	}
	return &FirebaseFCMSender{client: client}, nil
}

// Send delivers a data-only push message (no display notification) so the
// Flutter app can decrypt the payload before posting a local notification.
func (f *FirebaseFCMSender) Send(ctx context.Context, token, tag, rkey, payload string) error {
	msg := &messaging.Message{
		Token: token,
		Data: map[string]string{
			"tag":     tag,
			"rkey":    rkey,
			"payload": payload,
		},
		Android: &messaging.AndroidConfig{
			Priority: "high",
		},
		APNS: &messaging.APNSConfig{
			Headers: map[string]string{
				"apns-priority":  "10",
				"apns-push-type": "alert",
			},
		},
	}
	if _, err := f.client.Send(ctx, msg); err != nil {
		if messaging.IsUnregistered(err) {
			return ErrTokenUnregistered
		}
		return err
	}
	return nil
}
