package rdp

import "testing"

func TestRDPOrderCapabilityAdvertisesPatBltAndOpaqueRectOnlyAt32BPP(t *testing.T) {
	for _, test := range []struct {
		name string
		bpp  uint16
		want byte
	}{
		{name: "32 bpp complete pattern profile", bpp: 32, want: 1},
		{name: "16 bpp profile remains disabled", bpp: 16, want: 0},
		{name: "15 bpp profile remains disabled", bpp: 15, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			caps := marshalRDPClientCapabilitySets(MCSClientSettings{}, test.bpp)
			defer clear(caps)
			// General (24 bytes), bitmap (28 bytes), then the 88-byte order set.
			const orderOffset = 24 + 28
			const patBltIndexOffset = orderOffset + rdpOrderSupportOffset + rdpOrderSupportPatBltIndex
			if len(caps) < patBltIndexOffset+1 || caps[orderOffset] != byte(rdpCapOrder) {
				t.Fatalf("order capability missing or truncated: len=%d", len(caps))
			}
			if got := caps[patBltIndexOffset]; got != test.want {
				t.Fatalf("PatBlt/OpaqueRect orderSupport = %d, want %d", got, test.want)
			}
		})
	}
}

func TestRDPPrimaryOrderProfileEnablesPatBltAndOpaqueRectOnlyAt32BPP(t *testing.T) {
	for _, test := range []struct {
		bpp  uint16
		want bool
	}{{32, true}, {16, false}, {15, false}} {
		session := &CredSSPClientSession{serverCapabilities: RDPServerCapabilities{PreferredBitsPerPixel: test.bpp}}
		setRDPPrimaryOrderProfileLocked(session)
		if session.patBltOpaqueRectEnabled != test.want {
			t.Errorf("bpp=%d PatBlt/OpaqueRect enabled=%v, want %v", test.bpp, session.patBltOpaqueRectEnabled, test.want)
		}
	}
}

func TestRDPOrderCapabilityAdvertisesMultiOpaqueRectOnlyAt32BPP(t *testing.T) {
	for _, test := range []struct {
		name string
		bpp  uint16
		want byte
	}{
		{name: "32 bpp complete multi-rectangle profile", bpp: 32, want: 1},
		{name: "16 bpp profile remains disabled", bpp: 16, want: 0},
		{name: "15 bpp profile remains disabled", bpp: 15, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			caps := marshalRDPClientCapabilitySets(MCSClientSettings{}, test.bpp)
			defer clear(caps)
			const orderOffset = 24 + 28
			const multiOpaqueOffset = orderOffset + rdpOrderSupportOffset + rdpOrderSupportMultiOpaqueRectIndex
			if len(caps) <= multiOpaqueOffset || caps[orderOffset] != byte(rdpCapOrder) {
				t.Fatalf("order capability missing or truncated: len=%d", len(caps))
			}
			if got := caps[multiOpaqueOffset]; got != test.want {
				t.Fatalf("MultiOpaqueRect orderSupport = %d, want %d", got, test.want)
			}
		})
	}
}

func TestRDPPrimaryOrderProfileEnablesMultiOpaqueRectOnlyAt32BPP(t *testing.T) {
	for _, test := range []struct {
		bpp  uint16
		want bool
	}{{32, true}, {16, false}, {15, false}} {
		session := &CredSSPClientSession{serverCapabilities: RDPServerCapabilities{PreferredBitsPerPixel: test.bpp}}
		setRDPPrimaryOrderProfileLocked(session)
		if session.multiOpaqueRectEnabled != test.want {
			t.Errorf("bpp=%d MultiOpaqueRect enabled=%v, want %v", test.bpp, session.multiOpaqueRectEnabled, test.want)
		}
	}
}
