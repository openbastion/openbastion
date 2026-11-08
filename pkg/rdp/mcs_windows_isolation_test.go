package rdp

// ADR-0071, the Windows validation: Windows Server 2022 closes the connection after this client's
// MCS Connect-Initial (CI run #13: "reading MCS Connect-Response TPKT: EOF"). This test isolates
// why, without changing the protocol: each case is a fresh connection, CredSSP as the client does
// it, then one Connect-Initial that differs from the baseline by one block or one parameter, each
// taken from MS-RDPBCGR (the annotated client example of §4.1.3, sent by a Windows client). What
// Windows answers to each is the result; nothing here is a fix.
//
// It first rules out the other explanation: Windows never answers authInfo, and a rejected one is
// a closed connection, seen only when the Connect-Response is read. So each case first checks that
// the connection is still open after authInfo, before any MCS byte.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type isolationCase struct {
	name, source string
	// blocks changes the GCC client data blocks; nil keeps the baseline's.
	blocks func(core, cluster, security []byte) []byte
	// integer encodes the MCS domain parameters; nil keeps the canonical BER of the baseline.
	integer func(dst []byte, value uint32) []byte
}

// specInteger is how the MS-RDPBCGR §4.1.3 example encodes the domain parameters: the shortest
// big-endian bytes, without the leading zero a canonical BER INTEGER needs when the high bit is set
// (65535 as 02 02 ff ff, 64535 as 02 02 fc 17).
func specInteger(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	start := 0
	for start < 3 && encoded[start] == 0 {
		start++
	}
	return appendBER(dst, 0x02, encoded[start:])
}

func isolationConnectInitial(t *testing.T, settings MCSClientSettings, c isolationCase) []byte {
	t.Helper()
	baseline, err := marshalClientDataBlocks(settings)
	if err != nil {
		t.Fatal(err)
	}
	clientData := baseline
	if c.blocks != nil {
		// The baseline's blocks, in its order: core, cluster, security.
		blocks := map[uint16][]byte{}
		for rest := baseline; len(rest) >= 4; {
			kind, length := binary.LittleEndian.Uint16(rest[:2]), int(binary.LittleEndian.Uint16(rest[2:4]))
			blocks[kind] = append([]byte(nil), rest[4:length]...)
			rest = rest[length:]
		}
		clientData = c.blocks(blocks[gccClientCoreType], blocks[gccClientClusterType], blocks[gccClientSecurityType])
	}
	gcc, err := marshalGCCConferenceCreateRequest(clientData)
	if err != nil {
		t.Fatal(err)
	}
	var mcs []byte
	if c.integer == nil {
		mcs, err = marshalMCSConnectInitial(gcc)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		params := func(values []uint32) []byte {
			var encoded []byte
			for _, v := range values {
				encoded = c.integer(encoded, v)
			}
			return encoded
		}
		var body []byte
		body = appendBER(body, 0x04, []byte{1})
		body = appendBER(body, 0x04, []byte{1})
		body = appendBER(body, 0x01, []byte{0xff})
		body = appendBER(body, 0x30, params([]uint32{34, 2, 0, 1, 0, 1, 65535, 2}))
		body = appendBER(body, 0x30, params([]uint32{1, 1, 1, 1, 0, 1, 1056, 2}))
		body = appendBER(body, 0x30, params([]uint32{65535, 64535, 65535, 1, 0, 1, 65535, 2}))
		body = appendBER(body, 0x04, gcc)
		mcs = appendBERHighTag(nil, []byte{0x7f, mcsConnectInitialTag}, body)
	}
	packet := make([]byte, 7+len(mcs))
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet
}

func gccBlock(kind uint16, payload []byte) []byte { return appendGCCBlock(nil, kind, payload) }

// emptyNetwork is TS_UD_CS_NET with channelCount 0 (MS-RDPBCGR 2.2.1.3.4).
func emptyNetwork() []byte { return gccBlock(0xc003, make([]byte, 4)) }

func isolationCases() []isolationCase {
	keyboard := func(layout uint32) func(core, cluster, security []byte) []byte {
		return func(core, cluster, security []byte) []byte {
			core = append([]byte(nil), core...)
			binary.LittleEndian.PutUint32(core[12:16], layout) // version, width, height, colorDepth, SAS, then keyboardLayout
			return append(append(gccBlock(gccClientCoreType, core), gccBlock(gccClientClusterType, cluster)...), gccBlock(gccClientSecurityType, security)...)
		}
	}
	return []isolationCase{
		{name: "baseline", source: "the client as it is"},
		{name: "keyboardLayout 0x409", source: "§4.1.3: keyboardLayout = 0x00000409; the baseline sends 0", blocks: keyboard(0x409)},
		{name: "with CS_NET, no channel", source: "§4.1.3 sends TS_UD_CS_NET; 2.2.1.3.4: channelCount 0 is valid", blocks: func(core, cluster, security []byte) []byte {
			return append(append(append(gccBlock(gccClientCoreType, core), gccBlock(gccClientClusterType, cluster)...), gccBlock(gccClientSecurityType, security)...), emptyNetwork()...)
		}},
		{name: "§4.1.3 block order", source: "§4.1.3 order: core, security, network, cluster", blocks: func(core, cluster, security []byte) []byte {
			return append(append(append(gccBlock(gccClientCoreType, core), gccBlock(gccClientSecurityType, security)...), emptyNetwork()...), gccBlock(gccClientClusterType, cluster)...)
		}},
		{name: "§4.1.3 domain parameter integers", source: "§4.1.3: 65535 as 02 02 ff ff, 64535 as 02 02 fc 17", integer: specInteger},
		{name: "§4.1.3 integers, CS_NET, keyboardLayout 0x409", source: "the three together", integer: specInteger, blocks: func(core, cluster, security []byte) []byte {
			core = append([]byte(nil), core...)
			binary.LittleEndian.PutUint32(core[12:16], 0x409)
			return append(append(append(gccBlock(gccClientCoreType, core), gccBlock(gccClientSecurityType, security)...), emptyNetwork()...), gccBlock(gccClientClusterType, cluster)...)
		}},
	}
}

type isolationResult struct {
	openAfterAuthInfo string
	answer            string
}

func TestRDPWindowsIsolation_MCSConnectInitial(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
	address, user, password := os.Getenv("RDP_WINDOWS_ADDRESS"), os.Getenv("RDP_WINDOWS_USER"), os.Getenv("RDP_WINDOWS_PASSWORD")
	pin, name := os.Getenv("RDP_WINDOWS_PIN"), os.Getenv("RDP_WINDOWS_SERVER_NAME")
	raw, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		t.Fatal("RDP_WINDOWS_CA_FILE holds no certificate")
	}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	var report []string
	// First, no MCS byte at all: does Windows close on its own after authInfo, and when?
	silent := isolationSilence(t, address, user, password, pin, name, roots, 30*time.Second)
	line := fmt.Sprintf("%-46s | %s", "authInfo, then no MCS byte for 30 s", silent)
	t.Log(line)
	report = append(report, line)
	for _, c := range isolationCases() {
		packet := isolationConnectInitial(t, settings, c)
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
			file := strings.NewReplacer(" ", "-", ",", "", "§", "s", ".", "").Replace(c.name) + ".connect-initial.hex"
			_ = os.WriteFile(filepath.Join(dir, file), []byte(hex.Dump(packet)), 0o644)
		}
		result := isolationRun(t, address, user, password, pin, name, roots, packet)
		line := fmt.Sprintf("%-46s | after authInfo: %-28s | Connect-Initial (%d bytes): %s   [%s]", c.name, result.openAfterAuthInfo, len(packet), result.answer, c.source)
		t.Log(line)
		report = append(report, line)
		time.Sleep(2 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "mcs-isolation.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

func isolationRun(t *testing.T, address, user, password, pin, name string, roots *x509.CertPool, packet []byte) isolationResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transport, err := DialHybrid(ctx, TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
	if err != nil {
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("dial: %v", err)}
	}
	session, err := transport.EstablishCredSSP(ctx, CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second})
	if err != nil {
		_ = transport.Close()
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("CredSSP: %v", err)}
	}
	defer session.Close()
	conn := session.transport.Conn
	// Still open after authInfo? A read that times out says yes; EOF says Windows closed it.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var one [1]byte
	n, err := conn.Read(one[:])
	open := "open (no byte in 3 s)"
	var netErr net.Error
	switch {
	case n > 0:
		open = fmt.Sprintf("Windows sent 0x%02x unasked", one[0])
	case errors.As(err, &netErr) && netErr.Timeout():
	case err != nil:
		return isolationResult{openAfterAuthInfo: "CLOSED: " + err.Error(), answer: "not sent"}
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := writeFull(conn, packet); err != nil {
		return isolationResult{openAfterAuthInfo: open, answer: "write: " + err.Error()}
	}
	sent := time.Now()
	response, err := readTPKTPacket(conn, maxTPKTPacket)
	if err != nil {
		return isolationResult{openAfterAuthInfo: open, answer: fmt.Sprintf("NO ANSWER, closed %v after it: %v", time.Since(sent).Round(time.Millisecond), err)}
	}
	head := response
	if len(head) > 12 {
		head = head[:12]
	}
	if _, perr := ParseMCSConnectResponse(response); perr != nil {
		return isolationResult{openAfterAuthInfo: open, answer: fmt.Sprintf("ANSWERED %d bytes (% x…), not parsed: %v", len(response), head, perr)}
	}
	return isolationResult{openAfterAuthInfo: open, answer: fmt.Sprintf("CONNECT-RESPONSE %d bytes (% x…)", len(response), head)}
}

// The isolation compares with the client itself: its baseline is byte for byte what the client
// sends, and each case changes what it says and nothing else.
func TestRDPWindowsIsolation_TheBaselineIsTheClientsConnectInitial(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	want, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	cases := isolationCases()
	if got := isolationConnectInitial(t, settings, cases[0]); hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("the baseline is not the client's Connect-Initial:\n%x\n%x", got, want)
	}
	keyboard := isolationConnectInitial(t, settings, cases[1])
	if len(keyboard) != len(want) {
		t.Fatalf("keyboardLayout: %d bytes, want %d", len(keyboard), len(want))
	}
	diff := 0
	for i := range want {
		if keyboard[i] != want[i] {
			diff++
		}
	}
	if diff != 2 || !strings.Contains(hex.EncodeToString(keyboard), "09040000") {
		t.Fatalf("keyboardLayout: %d byte(s) differ, want the two of 0x0409", diff)
	}
	integers := isolationConnectInitial(t, settings, cases[4])
	for _, spec := range []string{"0202ffff", "0202fc17"} {
		if !strings.Contains(hex.EncodeToString(integers), spec) || strings.Contains(hex.EncodeToString(want), spec) {
			t.Fatalf("§4.1.3 integers: %s only in the variant", spec)
		}
	}
	if network := isolationConnectInitial(t, settings, cases[2]); len(network) != len(want)+8 || !strings.Contains(hex.EncodeToString(network), "03c0080000000000") {
		t.Fatalf("CS_NET: %d bytes, want %d with 03c0 0800 00000000", len(network), len(want)+8)
	}
}

// isolationSilence: CredSSP, then nothing; how long Windows keeps the connection, up to wait.
func isolationSilence(t *testing.T, address, user, password, pin, name string, roots *x509.CertPool, wait time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait+30*time.Second)
	defer cancel()
	transport, err := DialHybrid(ctx, TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
	if err != nil {
		return fmt.Sprintf("dial: %v", err)
	}
	session, err := transport.EstablishCredSSP(ctx, CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second})
	if err != nil {
		_ = transport.Close()
		return fmt.Sprintf("CredSSP: %v", err)
	}
	defer session.Close()
	conn := session.transport.Conn
	since := time.Now()
	_ = conn.SetReadDeadline(since.Add(wait))
	var one [1]byte
	n, err := conn.Read(one[:])
	var netErr net.Error
	switch {
	case n > 0:
		return fmt.Sprintf("Windows sent 0x%02x unasked after %v", one[0], time.Since(since).Round(time.Millisecond))
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Sprintf("still open after %v: Windows waits for the client", wait)
	default:
		return fmt.Sprintf("CLOSED by Windows %v after authInfo: %v", time.Since(since).Round(time.Millisecond), err)
	}
}
