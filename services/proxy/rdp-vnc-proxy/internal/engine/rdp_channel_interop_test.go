package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/rdp"
)

// The static channel of ADR-0095 (increment 1), against real servers: drdynvc announced, given an ID
// by the server, joined, and what the server sends on it read off the screen's stream, reassembled.
// The dynamic channels themselves are increment 2: here the messages are only counted and named.
// The first a server sends on drdynvc is its capabilities request (MS-RDPEDYC 2.2.1.1: Cmd 0x05).

type channelLog struct {
	mu       sync.Mutex
	messages [][]byte
}

func (l *channelLog) handle(channel string, message []byte) error {
	if channel != rdp.RDPChannelDynamic {
		return fmt.Errorf("a message on %q", channel)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, append([]byte(nil), message...))
	return nil
}

func (l *channelLog) snapshot() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]byte(nil), l.messages...)
}

// openWithStaticChannel runs the connection sequence of RDPCodec.Open by hand, drdynvc announced,
// then reads the screen for read, and returns what came on the channel.
func openWithStaticChannel(t *testing.T, client *rdp.CredSSPClientSession, user, password string, read time.Duration) [][]byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defer client.Close()
	settings := rdp.MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: rdpClientName,
		Timeout: 15 * time.Second, DynamicChannels: true}
	var log channelLog
	client.SetChannelHandler(log.handle)
	steps := []rdpConnectionStep{
		{"MCS connect", func() error {
			response, e := client.ConnectMCS(ctx, settings)
			if e == nil && len(response.StaticChannelIDs) != 1 {
				return fmt.Errorf("%d static channel ID(s) for one announced", len(response.StaticChannelIDs))
			}
			return e
		}},
		{"MCS channels", func() error { _, e := client.ConnectMCSChannels(ctx, 15*time.Second); return e }},
		{"client info", func() error {
			return client.SendClientInfo(ctx, rdp.RDPClientInfo{Username: user, Password: []byte(password)}, 15*time.Second)
		}},
		{"licensing", func() error { return client.CompleteLicensing(ctx, 15*time.Second) }},
		{"capabilities", func() error { _, e := client.ExchangeCapabilities(ctx, 15*time.Second); return e }},
		{"finalization", func() error { _, e := client.FinalizeConnection(ctx, 15*time.Second); return e }},
	}
	if err := runRDPConnectionSteps(ctx, steps); err != nil {
		t.Fatalf("the connection with drdynvc announced: %v", err)
	}
	if names := client.StaticChannels(); len(names) != 1 || names[0] != rdp.RDPChannelDynamic {
		t.Fatalf("channels joined: %q, want drdynvc", names)
	}
	updates := 0
	for deadline := time.Now().Add(read); time.Now().Before(deadline); {
		if _, err := client.ReadBitmapUpdate(ctx, time.Until(deadline)); err != nil {
			if errors.Is(err, rdp.ErrRDPChannel) {
				t.Fatalf("channel data refused after %d update(s): %v", updates, err)
			}
			break // the read's deadline, or the session's end: what came is in the log
		}
		updates++
	}
	messages := log.snapshot()
	t.Logf("%d screen update(s), %d drdynvc message(s)", updates, len(messages))
	for i, message := range messages {
		t.Logf("drdynvc message %d: %d bytes, first byte 0x%02x (Cmd %d)", i, len(message), message[0], message[0]>>4)
	}
	if updates == 0 {
		t.Fatal("no screen update with the channel joined")
	}
	return messages
}

func TestRDPInterop_StaticChannel(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client, err := target.authenticate(ctx, rdpInteropPassword)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	messages := openWithStaticChannel(t, client, rdpInteropUser, rdpInteropPassword, 5*time.Second)
	if len(messages) > 0 && messages[0][0]>>4 != 0x05 {
		t.Fatalf("FreeRDP's first drdynvc message has Cmd %d, not the capabilities request (5)", messages[0][0]>>4)
	}
}
