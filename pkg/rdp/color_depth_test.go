package rdp

import (
	"encoding/binary"
	"errors"
	"testing"
)

// The depth asked for at connection (ADR-0132): 16 bpp is asked as FreeRDP asks /bpp:16 —
// postBeta2ColorDepth and highColorDepth at 16, WANT_32BPP left out — and 0 and 32 keep the
// request as it was, to the byte. Any other depth sends nothing.
func TestMCSClientSettings_ColorDepth(t *testing.T) {
	core := func(depth uint16) ([]byte, error) {
		blocks, err := marshalClientDataBlocks(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", GraphicsPipeline: true, DynamicChannels: true, ColorDepth: depth})
		if err != nil {
			return nil, err
		}
		return blocks[4 : 4+212], nil
	}
	before, err := core(0)
	if err != nil {
		t.Fatal(err)
	}
	thirtyTwo, err := core(32)
	if err != nil || string(thirtyTwo) != string(before) {
		t.Fatalf("32 bpp is not the request as it was: %v", err)
	}
	if binary.LittleEndian.Uint16(before[128:130]) != rdpColor24BPP || binary.LittleEndian.Uint16(before[136:138]) != rdpHighColor24BPP ||
		binary.LittleEndian.Uint16(before[140:142]) != rdpClientErrInfo|rdpClientWant32BPP|rdpClientSupportGraphics {
		t.Fatalf("32 bpp: %x", before[128:142])
	}
	sixteen, err := core(16)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(sixteen[128:130]); got != 0xca03 {
		t.Fatalf("16 bpp: postBeta2ColorDepth 0x%04x, want RNS_UD_COLOR_16BPP_565", got)
	}
	if got := binary.LittleEndian.Uint16(sixteen[136:138]); got != 16 {
		t.Fatalf("16 bpp: highColorDepth %d", got)
	}
	if got := binary.LittleEndian.Uint16(sixteen[138:140]); got != rdpSupportedColorDepths {
		t.Fatalf("16 bpp: supportedColorDepths 0x%04x, want every depth as before (ADR-0071)", got)
	}
	if got := binary.LittleEndian.Uint16(sixteen[140:142]); got != rdpClientErrInfo|rdpClientSupportGraphics {
		t.Fatalf("16 bpp: earlyCapabilityFlags 0x%04x, want WANT_32BPP left out and the rest kept", got)
	}
	for _, depth := range []uint16{8, 15, 24, 33} {
		if _, err := core(depth); !errors.Is(err, ErrMCSConnection) {
			t.Fatalf("%d bpp: %v, want refused", depth, err)
		}
	}
}
