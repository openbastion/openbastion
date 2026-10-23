package infrastructure_test

// The signature of a webhook delivery (ADR-0013). The receiver in this file is written
// from the DESCRIPTION of the contract — v1=hex(HMAC-SHA256(secret, timestamp "." body)),
// compared in constant time, timestamp checked against its own clock — and not from the
// notifier's code: if the notifier and this receiver agree, an actual receiver written
// in any language from the same description will.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

const testSecret = "0123456789abcdef0123456789abcdef-SECRETKEY" // 42 bytes

type signedDelivery struct {
	raw       []byte
	timestamp string
	signature string
	headers   http.Header
}

func signedReceiver(t *testing.T) (*httptest.Server, chan signedDelivery) {
	t.Helper()
	got := make(chan signedDelivery, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got <- signedDelivery{raw, r.Header.Get("X-OpenBastion-Timestamp"), r.Header.Get("X-OpenBastion-Signature"), r.Header.Clone()}
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func nextSigned(t *testing.T, ch chan signedDelivery) signedDelivery {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(3 * time.Second):
		t.Fatal("nothing was delivered")
		return signedDelivery{}
	}
}

// receiverVerifies is what a receiver does with a delivery.
func receiverVerifies(secret string, d signedDelivery, now time.Time, tolerance time.Duration) bool {
	ts, err := strconv.ParseInt(d.timestamp, 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(ts, 0))
	if age < -tolerance || age > tolerance {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(d.timestamp + "."))
	mac.Write(d.raw)
	want := "v1=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(d.signature))
}

func signingNotifier(t *testing.T, url string, clock func() time.Time) *infrastructure.WebhookNotifier {
	t.Helper()
	n, err := infrastructure.NewWebhookNotifier(url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.WithSecret(testSecret); err != nil {
		t.Fatal(err)
	}
	return n.WithClock(clock)
}

func TestWebhookSignature_AReceiverCanVerifyWhatItReceives(t *testing.T) {
	srv, got := signedReceiver(t)
	at := time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)
	n := signingNotifier(t, srv.URL+"/hook", func() time.Time { return at })
	if !n.Signed() {
		t.Fatal("a notifier with a secret says it is not signing")
	}

	n.Notify(context.Background(), requested)
	d := nextSigned(t, got)

	if d.timestamp != strconv.FormatInt(at.Unix(), 10) {
		t.Fatalf("timestamp = %q, want the time of sending (%d)", d.timestamp, at.Unix())
	}
	if !strings.HasPrefix(d.signature, "v1=") || len(d.signature) != len("v1=")+64 {
		t.Fatalf("signature = %q, want v1= and 64 hex characters", d.signature)
	}
	if !receiverVerifies(testSecret, d, at, 5*time.Minute) {
		t.Fatalf("a receiver cannot verify the delivery: ts=%s sig=%s body=%s", d.timestamp, d.signature, d.raw)
	}
	// Control: the same check refuses everything that is not exactly this delivery.
	tampered := d
	tampered.raw = append([]byte(nil), d.raw...)
	tampered.raw[len(tampered.raw)/2] ^= 0x01 // one bit of the body
	if receiverVerifies(testSecret, tampered, at, 5*time.Minute) {
		t.Fatal("a body that was changed still verifies")
	}
	if receiverVerifies(testSecret+"x", d, at, 5*time.Minute) {
		t.Fatal("another secret verifies")
	}
	restamped := d
	restamped.timestamp = strconv.FormatInt(at.Unix()+1, 10)
	if receiverVerifies(testSecret, restamped, at, 5*time.Minute) {
		t.Fatal("a different timestamp verifies: it is not part of what is signed")
	}
	if receiverVerifies(testSecret, d, at.Add(6*time.Minute), 5*time.Minute) {
		t.Fatal("a delivery six minutes old verifies with a tolerance of five")
	}
	if receiverVerifies(testSecret, d, at.Add(-6*time.Minute), 5*time.Minute) {
		t.Fatal("a delivery from six minutes in the future verifies with a tolerance of five")
	}
}

// The timestamp is that of the delivery, so that what a receiver's tolerance measures is
// how fresh the delivery is.
func TestWebhookSignature_EachDeliveryIsStampedWhenItIsSent(t *testing.T) {
	srv, got := signedReceiver(t)
	var mu sync.Mutex
	at := time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)
	n := signingNotifier(t, srv.URL+"/hook", func() time.Time { mu.Lock(); defer mu.Unlock(); return at })

	n.Notify(context.Background(), requested)
	first := nextSigned(t, got)
	mu.Lock()
	at = at.Add(90 * time.Second)
	mu.Unlock()
	n.Notify(context.Background(), requested)
	second := nextSigned(t, got)

	if first.timestamp == second.timestamp || first.signature == second.signature {
		t.Fatalf("two deliveries 90 s apart carry the same stamp or signature: %s / %s", first.timestamp, second.timestamp)
	}
	if !receiverVerifies(testSecret, first, at.Add(-90*time.Second), time.Minute) || !receiverVerifies(testSecret, second, at, time.Minute) {
		t.Fatal("a delivery does not verify at the time it was sent")
	}
}

func TestWebhookSignature_WithoutASecretNothingIsSigned(t *testing.T) {
	srv, got := signedReceiver(t)
	n, _ := infrastructure.NewWebhookNotifier(srv.URL + "/hook")
	if n.Signed() {
		t.Fatal("a notifier without a secret says it is signing")
	}
	n.Notify(context.Background(), requested)
	d := nextSigned(t, got)
	for _, h := range []string{"X-OpenBastion-Signature", "X-OpenBastion-Timestamp"} {
		if v := d.headers.Values(h); len(v) != 0 {
			t.Fatalf("an unsigned delivery carries %s: %v", h, v)
		}
	}
}

// A key shorter than the output of the function it feeds is a weak key; and the refusal
// is written into a log, so it must not repeat what it refuses.
func TestWebhookSignature_AShortSecretIsRefused_WithoutBeingRepeated(t *testing.T) {
	for _, secret := range []string{"", "a", "SECRET-ABC-DEF-0123456789", strings.Repeat("k", 31)} {
		n, _ := infrastructure.NewWebhookNotifier("https://hooks.example.com/x")
		got, err := n.WithSecret(secret)
		if err == nil || got != nil {
			t.Fatalf("a secret of %d bytes was accepted", len(secret))
		}
		if len(secret) >= 8 && strings.Contains(err.Error(), secret) { // shorter ones are inside any sentence
			t.Fatalf("the refusal repeats the secret: %v", err)
		}
		if !strings.Contains(err.Error(), "32") {
			t.Fatalf("the refusal does not say the minimum: %v", err)
		}
		if n.Signed() {
			t.Fatal("a refused secret left the notifier signing")
		}
	}
	n, _ := infrastructure.NewWebhookNotifier("https://hooks.example.com/x")
	if _, err := n.WithSecret(strings.Repeat("k", 32)); err != nil || !n.Signed() {
		t.Fatalf("a secret of exactly 32 bytes: %v (signed=%v)", err, n.Signed())
	}
}

// The secret is a secret: not in what is sent, not in what is logged — whatever happens
// to the delivery.
func TestWebhookSignature_TheSecretIsNeverSentNorLogged(t *testing.T) {
	srv, got := signedReceiver(t)
	n := signingNotifier(t, srv.URL+"/hook", time.Now)
	n.Notify(context.Background(), requested)
	d := nextSigned(t, got)
	if strings.Contains(string(d.raw), "SECRETKEY") {
		t.Fatalf("the secret is in the body: %s", d.raw)
	}
	for name, values := range d.headers {
		for _, v := range values {
			if strings.Contains(v, "SECRETKEY") || strings.Contains(v, testSecret) {
				t.Fatalf("the secret is in the header %s: %s", name, v)
			}
		}
	}

	// And through each way a delivery can fail.
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusInternalServerError) }))
	defer refusing.Close()
	for name, base := range map[string]string{"nobody listens": closedURL, "refused": refusing.URL} {
		t.Run(name, func(t *testing.T) {
			failing := signingNotifier(t, base+"/hook", time.Now)
			logs := newLogLines()
			failing.WithLogf(logs.logf)
			failing.Notify(context.Background(), requested)
			logs.next(t)
			if strings.Contains(logs.all(), "SECRETKEY") || strings.Contains(logs.all(), testSecret) {
				t.Fatalf("the secret leaked into the log: %s", logs.all())
			}
		})
	}
}

// What is signed is the whole message, including the human text, whatever it carries.
func TestWebhookSignature_CoversTheWholeBody_WhateverItCarries(t *testing.T) {
	srv, got := signedReceiver(t)
	n := signingNotifier(t, srv.URL+"/hook", time.Now)
	hostile := requested
	hostile.AccountID = "acc\"},\"x\":{\"<@channel> \n"
	hostile.Event = domain.NotifyBreakGlassApproved
	hostile.DecidedBy = "user-lead"
	n.Notify(context.Background(), hostile)
	d := nextSigned(t, got)
	if !receiverVerifies(testSecret, d, time.Now(), time.Minute) {
		t.Fatalf("a body with awkward characters does not verify: %s", d.raw)
	}
}
