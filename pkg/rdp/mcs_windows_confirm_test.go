package rdp

// ADR-0071, the Windows validation, the capability exchange. CI run #31: right after this client's
// Confirm Active, Windows sends a Set Error Info PDU, errorInfo 0x000010EA (ERRINFO_BADCAPABILITIES,
// MS-RDPBCGR 2.2.5.1.1: the client's capabilities are not accepted), and closes. One candidate is
// written in the specification: bitmapCompressionFlag "MUST be set to TRUE" (2.2.7.1.2), and this
// client sends 0. This bisects it as the Connect-Initial was: each case a fresh connection through
// Licensing, then this client's Confirm Active with one change, against FreeRDP's capability sets
// (from its recording) where it differs. Windows' verdict: a Set Error Info within 3 s is a refusal;
// silence is acceptance (Windows then waits for the client's finalization PDUs).
//
//	RDP_WINDOWS=1 RDP_WINDOWS_FREERDP_RECORD=… go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"bytes"
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

type capabilitySet struct {
	kind uint16
	data []byte // the whole set, header included
}

// confirmActiveShare returns the Share Control PDU of a Confirm Active TPKT packet.
func confirmActiveShare(packet []byte) ([]byte, error) {
	if len(packet) < 9 || packet[0] != 3 || !bytes.Equal(packet[4:7], []byte{2, 0xf0, 0x80}) || packet[7] != 0x64 {
		return nil, fmt.Errorf("not an MCS Send Data Request")
	}
	mcs := packet[7:]
	if len(mcs) < 7 || mcs[5] != 0x70 {
		return nil, fmt.Errorf("MCS header")
	}
	length, share, err := readPERLength(mcs[6:])
	if err != nil || length != len(share) || len(share) < 18 || binary.LittleEndian.Uint16(share[2:4])&0x0f != 3 {
		return nil, fmt.Errorf("not a Confirm Active")
	}
	return share, nil
}

// confirmActiveCapabilities splits a Confirm Active's capability sets.
func confirmActiveCapabilities(share []byte) ([]capabilitySet, error) {
	sourceLength := int(binary.LittleEndian.Uint16(share[12:14]))
	combined := int(binary.LittleEndian.Uint16(share[14:16]))
	if 16+sourceLength+combined > len(share) || combined < 4 {
		return nil, fmt.Errorf("lengths")
	}
	data := share[16+sourceLength : 16+sourceLength+combined]
	count := int(binary.LittleEndian.Uint16(data[:2]))
	data = data[4:]
	var sets []capabilitySet
	for i := 0; i < count; i++ {
		if len(data) < 4 {
			return nil, fmt.Errorf("set %d truncated", i)
		}
		size := int(binary.LittleEndian.Uint16(data[2:4]))
		if size < 4 || size > len(data) {
			return nil, fmt.Errorf("set %d: %d bytes", i, size)
		}
		sets = append(sets, capabilitySet{kind: binary.LittleEndian.Uint16(data[:2]), data: append([]byte(nil), data[:size]...)})
		data = data[size:]
	}
	return sets, nil
}

// confirmActiveWith is this client's Confirm Active share with other capability sets: the same
// header, source and share ID, re-encoded as the client encodes it.
func confirmActiveWith(share []byte, sets []capabilitySet, userID uint16) ([]byte, error) {
	sourceLength := int(binary.LittleEndian.Uint16(share[12:14]))
	var caps []byte
	for _, set := range sets {
		caps = append(caps, set.data...)
	}
	out := make([]byte, 16+sourceLength+4+len(caps))
	copy(out, share[:16+sourceLength])
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[14:16], uint16(4+len(caps)))
	binary.LittleEndian.PutUint16(out[16+sourceLength:], uint16(len(sets)))
	copy(out[16+sourceLength+4:], caps)
	return marshalMCSSendDataRequest(userID, mcsGlobalChannelID, out)
}

// findConfirmActive returns the first Confirm Active TPKT packet in a FreeRDP recording, or nil.
func findConfirmActive(data []byte) []byte {
	for i := 0; i+8 <= len(data); i++ {
		if data[i] != 3 || data[i+1] != 0 || !bytes.Equal(data[i+4:i+7], []byte{2, 0xf0, 0x80}) || data[i+7] != 0x64 {
			continue
		}
		length := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if length < 9 || i+length > len(data) {
			continue
		}
		if _, err := confirmActiveShare(data[i : i+length]); err == nil {
			return append([]byte(nil), data[i:i+length]...)
		}
	}
	return nil
}

type confirmCase struct {
	name string
	sets func(ours []capabilitySet) []capabilitySet
}

func withCompression(sets []capabilitySet) []capabilitySet {
	out := append([]capabilitySet(nil), sets...)
	for i, set := range out {
		if set.kind == rdpCapBitmap && len(set.data) == 28 {
			data := append([]byte(nil), set.data...)
			binary.LittleEndian.PutUint16(data[20:22], 1) // bitmapCompressionFlag
			out[i] = capabilitySet{kind: set.kind, data: data}
		}
	}
	return out
}

func confirmCases(freerdp []capabilitySet) []confirmCase {
	cases := []confirmCase{
		{"this client's", func(ours []capabilitySet) []capabilitySet { return ours }},
		{"with bitmapCompressionFlag TRUE", withCompression},
	}
	if freerdp == nil {
		return cases
	}
	cases = append(cases, confirmCase{"FreeRDP's sets", func([]capabilitySet) []capabilitySet { return freerdp }})
	have := map[uint16]bool{}
	for _, set := range []uint16{rdpCapGeneral, rdpCapBitmap, rdpCapOrder, rdpCapPointer, rdpCapInput} {
		have[set] = true
	}
	for _, set := range freerdp {
		set := set
		if have[set.kind] {
			cases = append(cases, confirmCase{fmt.Sprintf("FreeRDP's set 0x%04x in place of this client's", set.kind), func(ours []capabilitySet) []capabilitySet {
				out := append([]capabilitySet(nil), ours...)
				for i := range out {
					if out[i].kind == set.kind {
						out[i] = set
					}
				}
				return out
			}})
			continue
		}
		cases = append(cases, confirmCase{fmt.Sprintf("with FreeRDP's set 0x%04x added", set.kind), func(ours []capabilitySet) []capabilitySet {
			return append(append([]capabilitySet(nil), ours...), set)
		}})
	}
	cases = append(cases, confirmCase{"with bitmapCompressionFlag TRUE and all FreeRDP's other sets", func(ours []capabilitySet) []capabilitySet {
		out := withCompression(ours)
		for _, set := range freerdp {
			if !have[set.kind] {
				out = append(out, set)
			}
		}
		return out
	}})
	return cases
}

func TestRDPWindowsIsolation_ConfirmActive(t *testing.T) {
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
	var report []string
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		report = append(report, line)
	}
	var freerdp []capabilitySet
	if file := os.Getenv("RDP_WINDOWS_FREERDP_RECORD"); file != "" {
		recorded, err := os.ReadFile(file)
		packet := findConfirmActive(recorded)
		clear(recorded) // FreeRDP's recording holds the password; only its Confirm Active is kept.
		if err == nil && packet != nil {
			if share, err := confirmActiveShare(packet); err == nil {
				freerdp, _ = confirmActiveCapabilities(share)
			}
		}
		var kinds []string
		for _, set := range freerdp {
			kinds = append(kinds, fmt.Sprintf("0x%04x (%d)", set.kind, len(set.data)))
		}
		logf("FreeRDP's Confirm Active sets: %s", strings.Join(kinds, ", "))
	}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	for _, c := range confirmCases(freerdp) {
		logf("%-60s | %s", c.name, confirmRun(address, pin, name, roots, user, password, settings, c))
		time.Sleep(2 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "confirm-active-bisect.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

func confirmRun(address, pin, name string, roots *x509.CertPool, user, password string, settings MCSClientSettings, c confirmCase) string {
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		return err.Error()
	}
	defer done()
	for _, step := range sequenceSteps(settings, user, password, "Licensing") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := step.run(ctx, session)
		cancel()
		if err != nil {
			return fmt.Sprintf("%s: %v", step.name, err)
		}
	}
	conn := session.transport.Conn
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	demand, err := readMCSConnectResponse(conn)
	if err != nil {
		return fmt.Sprintf("Demand Active: %v", err)
	}
	capabilities, err := parseRDPDemandActive(demand, session.mcsResponse.IOChannelID)
	if err != nil {
		return fmt.Sprintf("Demand Active refused by this client: %v", err)
	}
	ours, err := marshalRDPConfirmActive(capabilities, session.mcsSettings, session.userChannelID)
	if err != nil {
		return fmt.Sprintf("Confirm Active: %v", err)
	}
	share, err := confirmActiveShare(ours)
	if err != nil {
		return fmt.Sprintf("Confirm Active share: %v", err)
	}
	sets, err := confirmActiveCapabilities(share)
	if err != nil {
		return fmt.Sprintf("Confirm Active sets: %v", err)
	}
	packet, err := confirmActiveWith(share, c.sets(sets), session.userChannelID)
	if err != nil {
		return fmt.Sprintf("Confirm Active variant: %v", err)
	}
	if err := writeFull(conn, packet); err != nil {
		return fmt.Sprintf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	answer, err := readSlowOrFastPathPacket(conn)
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		return "ACCEPTED: silent 3 s, waiting for the client's finalization"
	case err != nil:
		return fmt.Sprintf("closed: %v", err)
	}
	if code, ok := setErrorInfo(answer); ok {
		return fmt.Sprintf("REFUSED: Set Error Info 0x%08x", code)
	}
	head := answer
	if len(head) > 32 {
		head = head[:32]
	}
	return fmt.Sprintf("answered %d bytes: % x", len(answer), head)
}

// setErrorInfo reads a slow-path Set Error Info PDU (MS-RDPBCGR 2.2.5.1.1), pduType2 0x2f.
func setErrorInfo(packet []byte) (uint32, bool) {
	if len(packet) < 7+7 || packet[0] != 3 || packet[7] != mcsSendDataIndication {
		return 0, false
	}
	_, share, err := readPERLength(packet[7+6:])
	if err != nil || len(share) < 22 || binary.LittleEndian.Uint16(share[2:4])&0x0f != 7 || share[14] != 0x2f {
		return 0, false
	}
	return binary.LittleEndian.Uint32(share[18:22]), true
}

// The pieces are what they say: the client's Confirm Active re-encoded from its own sets is itself;
// the compression case changes one field; Windows' refusal of run #31 decodes as 0x10EA.
func TestRDPWindowsIsolation_ConfirmActivePieces(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: time.Second}
	ours, err := marshalRDPConfirmActive(RDPServerCapabilities{ShareID: 0x000103ea}, settings, 1007)
	if err != nil {
		t.Fatal(err)
	}
	share, err := confirmActiveShare(ours)
	if err != nil {
		t.Fatal(err)
	}
	sets, err := confirmActiveCapabilities(share)
	if err != nil || len(sets) != rdpClientCapabilitySetCount {
		t.Fatalf("sets: %v, %d", err, len(sets))
	}
	again, err := confirmActiveWith(share, sets, 1007)
	if err != nil || !bytes.Equal(again, ours) {
		t.Fatalf("re-encoded: %v, equal %v", err, bytes.Equal(again, ours))
	}
	// The compression case sets bitmapCompressionFlag and nothing else (the client now sends TRUE
	// itself, so on its own sets it changes nothing).
	zeroed := append([]capabilitySet(nil), sets...)
	for i := range zeroed {
		if zeroed[i].kind == rdpCapBitmap {
			data := append([]byte(nil), zeroed[i].data...)
			binary.LittleEndian.PutUint16(data[20:22], 0)
			zeroed[i] = capabilitySet{kind: rdpCapBitmap, data: data}
		}
	}
	compressed := withCompression(zeroed)
	for i := range zeroed {
		diff := 0
		for j := range zeroed[i].data {
			if zeroed[i].data[j] != compressed[i].data[j] {
				diff++
			}
		}
		if want := map[bool]int{true: 1, false: 0}[zeroed[i].kind == rdpCapBitmap]; diff != want {
			t.Fatalf("set 0x%04x: %d bytes changed", zeroed[i].kind, diff)
		}
	}
	if findConfirmActive(append([]byte{0xaa, 3, 0}, ours...)) == nil {
		t.Fatal("findConfirmActive")
	}
	// Run #31, packet 1, as Windows sent it.
	windows, err := hex.DecodeString("0300002402f08068000103eb3016160017000000ea030100000116002f000000ea100000")
	if err != nil {
		t.Fatal(err)
	}
	if code, ok := setErrorInfo(windows); !ok || code != 0x000010ea {
		t.Fatalf("Set Error Info: %#x, %v", code, ok)
	}
}
