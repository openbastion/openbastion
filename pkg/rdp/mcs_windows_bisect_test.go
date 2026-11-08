package rdp

// ADR-0071, the Windows validation, third isolation. CI run #24: FreeRDP's own Connect-Initial,
// sent after this client's CredSSP and TLS, gets a Connect-Response from Windows; this client's is
// closed 1 ms after it. The cause is what this client's Connect-Initial says. This bisects it: one
// fresh connection per case, this client's CredSSP and TLS, then FreeRDP's Connect-Initial with one
// of this client's GCC blocks, or one of this client's CS_CORE fields, put in. The first that
// Windows stops answering names the cause; FreeRDP's recorded and re-encoded packets are controls.
//
// gordp (github.com/casvisor/gordp, read as a reference, nothing taken) sends version 0x00080004
// as this client does, and agrees with FreeRDP where this client differs: postBeta2ColorDepth
// 0xCA01, an empty clientDigProductId, encryptionMethods 0, a valid connectionType, a clientBuild.
//
//	RDP_WINDOWS=1 RDP_WINDOWS_FREERDP_RECORD=… go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	gccClientNetworkType        = uint16(0xc003)
	gccClientMessageChannelType = uint16(0xc006)
	gccClientMultitransportType = uint16(0xc00a)
)

type gccDataBlock struct {
	kind    uint16
	payload []byte
}

// connectInitialBlocks returns the GCC client data blocks of a Connect-Initial, in order.
func connectInitialBlocks(packet []byte) ([]gccDataBlock, error) {
	at := bytes.Index(packet, []byte("Duca"))
	if at < 0 || at+6 > len(packet) {
		return nil, fmt.Errorf("no H.221 key")
	}
	rest := packet[at+4:]
	length := int(rest[0])
	rest = rest[1:]
	if length&0x80 != 0 {
		length = (length&0x7f)<<8 | int(rest[0])
		rest = rest[1:]
	}
	if length != len(rest) {
		return nil, fmt.Errorf("client data: %d bytes announced, %d present", length, len(rest))
	}
	var blocks []gccDataBlock
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("truncated block header")
		}
		kind, size := binary.LittleEndian.Uint16(rest[:2]), int(binary.LittleEndian.Uint16(rest[2:4]))
		if size < 4 || size > len(rest) {
			return nil, fmt.Errorf("block 0x%04x: %d bytes", kind, size)
		}
		blocks = append(blocks, gccDataBlock{kind: kind, payload: append([]byte(nil), rest[4:size]...)})
		rest = rest[size:]
	}
	return blocks, nil
}

// connectInitialFromBlocks encodes blocks as this client encodes its own Connect-Initial.
func connectInitialFromBlocks(blocks []gccDataBlock) ([]byte, error) {
	var clientData []byte
	for _, b := range blocks {
		clientData = appendGCCBlock(clientData, b.kind, b.payload)
	}
	gcc, err := marshalGCCConferenceCreateRequest(clientData)
	if err != nil {
		return nil, err
	}
	mcs, err := marshalMCSConnectInitial(gcc)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 7+len(mcs))
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet, nil
}

func blockOf(blocks []gccDataBlock, kind uint16) []byte {
	for _, b := range blocks {
		if b.kind == kind {
			return b.payload
		}
	}
	return nil
}

// withBlock replaces (payload) or drops (nil) the block of that kind; a missing one is not added.
func withBlock(blocks []gccDataBlock, kind uint16, payload []byte) []gccDataBlock {
	var out []gccDataBlock
	for _, b := range blocks {
		switch {
		case b.kind != kind:
			out = append(out, b)
		case payload != nil:
			out = append(out, gccDataBlock{kind: kind, payload: payload})
		}
	}
	return out
}

// coreField is a field of TS_UD_CS_CORE (MS-RDPBCGR 2.2.1.3.2), by offset in the block's payload.
type coreField struct {
	name       string
	start, end int
}

var coreFields = []coreField{
	{"version", 0, 4}, {"colorDepth", 8, 10}, {"keyboardLayout", 12, 16}, {"clientBuild", 16, 20},
	{"clientName", 20, 52}, {"postBeta2ColorDepth", 128, 130}, {"highColorDepth and supportedColorDepths", 136, 140},
	{"earlyCapabilityFlags", 140, 142}, {"clientDigProductId", 142, 206}, {"connectionType", 206, 207},
}

type bisectCase struct {
	name   string
	blocks []gccDataBlock // nil: send the recorded packet as it is
}

func bisectCases(freerdp, ours []gccDataBlock) []bisectCase {
	core := blockOf(freerdp, gccClientCoreType)
	ourCore := blockOf(ours, gccClientCoreType)
	cases := []bisectCase{
		{name: "FreeRDP's, as recorded"},
		{name: "FreeRDP's, re-encoded by this client", blocks: freerdp},
		{name: "FreeRDP's with this client's CS_CORE", blocks: withBlock(freerdp, gccClientCoreType, ourCore)},
		{name: "FreeRDP's with this client's CS_SECURITY", blocks: withBlock(freerdp, gccClientSecurityType, blockOf(ours, gccClientSecurityType))},
		{name: "FreeRDP's with this client's CS_CLUSTER", blocks: withBlock(freerdp, gccClientClusterType, blockOf(ours, gccClientClusterType))},
		{name: "FreeRDP's without CS_NET", blocks: withBlock(freerdp, gccClientNetworkType, nil)},
		{name: "FreeRDP's without CS_MULTITRANSPORT, CS_MCS_MSGCHANNEL", blocks: withBlock(withBlock(freerdp, gccClientMultitransportType, nil), gccClientMessageChannelType, nil)},
		{name: "this client's with FreeRDP's CS_CORE", blocks: withBlock(ours, gccClientCoreType, core)},
		{name: "this client's with FreeRDP's CS_CORE, CS_SECURITY", blocks: withBlock(withBlock(ours, gccClientCoreType, core), gccClientSecurityType, blockOf(freerdp, gccClientSecurityType))},
	}
	if len(core) >= 212 && len(ourCore) == 212 {
		for _, f := range coreFields {
			patched := append([]byte(nil), core...)
			copy(patched[f.start:f.end], ourCore[f.start:f.end])
			cases = append(cases, bisectCase{name: "FreeRDP's CS_CORE with this client's " + f.name, blocks: withBlock(freerdp, gccClientCoreType, patched)})
		}
		cases = append(cases, bisectCase{name: "FreeRDP's CS_CORE cut at serverSelectedProtocol", blocks: withBlock(freerdp, gccClientCoreType, append([]byte(nil), core[:212]...))})
	}
	return cases
}

func TestRDPWindowsIsolation_ConnectInitialBisect(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
	file := os.Getenv("RDP_WINDOWS_FREERDP_RECORD")
	if file == "" {
		t.Skip("RDP_WINDOWS_FREERDP_RECORD not set: the bisection starts from FreeRDP's Connect-Initial")
	}
	recorded, err := os.ReadFile(file)
	freerdpPacket := findConnectInitial(recorded)
	clear(recorded) // FreeRDP's recording holds the password; only the Connect-Initial is kept.
	if err != nil || freerdpPacket == nil {
		t.Fatalf("FreeRDP's Connect-Initial: %v", err)
	}
	freerdp, err := connectInitialBlocks(freerdpPacket)
	if err != nil {
		t.Fatalf("FreeRDP's blocks: %v", err)
	}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	ourPacket, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := connectInitialBlocks(ourPacket)
	if err != nil {
		t.Fatal(err)
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
	var kinds []string
	for _, b := range freerdp {
		kinds = append(kinds, fmt.Sprintf("0x%04x (%d bytes)", b.kind, len(b.payload)+4))
	}
	report := []string{"FreeRDP's blocks: " + strings.Join(kinds, ", ")}
	for _, c := range bisectCases(freerdp, ours) {
		packet := freerdpPacket
		if c.blocks != nil {
			if packet, err = connectInitialFromBlocks(c.blocks); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		cfg := CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second}
		result, _ := authInfoRun(address, pin, name, roots, 0, cfg, settings, packet)
		line := fmt.Sprintf("%-62s | %d bytes | %s", c.name, len(packet), result.answer)
		t.Log(line)
		report = append(report, line)
		time.Sleep(2 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "connect-initial-bisect.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

// The bisection's pieces do what they say: this client's packet re-encoded from its own blocks is
// byte for byte itself, and each core-field case changes only that field.
func TestRDPWindowsIsolation_BisectPieces(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: time.Second}
	packet, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := connectInitialBlocks(packet)
	if err != nil || len(ours) != 3 {
		t.Fatalf("blocks: %v, %d", err, len(ours))
	}
	again, err := connectInitialFromBlocks(ours)
	if err != nil || !bytes.Equal(again, packet) {
		t.Fatalf("re-encoded: %v, equal %v", err, bytes.Equal(again, packet))
	}
	// A FreeRDP-like peer: a 230-byte CS_CORE of 0xee, and the network block.
	core := bytes.Repeat([]byte{0xee}, 230)
	peer := []gccDataBlock{{gccClientCoreType, core}, {gccClientNetworkType, make([]byte, 4)}, {gccClientSecurityType, make([]byte, 8)}}
	for _, c := range bisectCases(peer, ours) {
		if !strings.HasPrefix(c.name, "FreeRDP's CS_CORE with this client's ") {
			continue
		}
		var field coreField
		for _, f := range coreFields {
			if strings.HasSuffix(c.name, " "+f.name) {
				field = f
			}
		}
		patched := blockOf(c.blocks, gccClientCoreType)
		changed := 0
		for i := range patched {
			if patched[i] != 0xee {
				changed++
				if i < field.start || i >= field.end {
					t.Errorf("%s: byte %d changed, outside [%d, %d)", c.name, i, field.start, field.end)
				}
			}
		}
		if len(patched) != 230 || changed == 0 {
			t.Errorf("%s: %d bytes, %d changed", c.name, len(patched), changed)
		}
		if len(c.blocks) != 3 || blockOf(c.blocks, gccClientNetworkType) == nil {
			t.Errorf("%s: the other blocks must stay", c.name)
		}
	}
	if got := withBlock(peer, gccClientNetworkType, nil); len(got) != 2 || blockOf(got, gccClientNetworkType) != nil {
		t.Error("withBlock(nil) must drop the block")
	}
}
