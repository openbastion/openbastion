package rdp

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// The graphics pipeline (MS-RDPEGFX), ADR-0101 increment 1: the channel and the capabilities. Once
// the target opens the channel, the client advertises what it accepts, and the target confirms one
// of those capability sets before anything else. The client advertises only sets that let it refuse
// the H.264 codecs (AVC_DISABLED from version 10), and none that would have it hold a cache of more
// than 16 MB (SMALL_CACHE). The other PDUs are read, bounded and handed to the caller; drawing them
// is for the increments that follow, and RemoteFX, which no flag turns off, is refused there.

// RDPGraphicsChannel is the dynamic channel of the graphics pipeline (MS-RDPEGFX 2.1).
const RDPGraphicsChannel = "Microsoft::Windows::RDS::Graphics"

// The commands of the graphics pipeline (MS-RDPEGFX 2.2.1.5).
const (
	RDPGraphicsWireToSurface1         = uint16(0x0001)
	RDPGraphicsWireToSurface2         = uint16(0x0002)
	RDPGraphicsDeleteEncodingContext  = uint16(0x0003)
	RDPGraphicsSolidFill              = uint16(0x0004)
	RDPGraphicsSurfaceToSurface       = uint16(0x0005)
	RDPGraphicsSurfaceToCache         = uint16(0x0006)
	RDPGraphicsCacheToSurface         = uint16(0x0007)
	RDPGraphicsEvictCacheEntry        = uint16(0x0008)
	RDPGraphicsCreateSurface          = uint16(0x0009)
	RDPGraphicsDeleteSurface          = uint16(0x000a)
	RDPGraphicsStartFrame             = uint16(0x000b)
	RDPGraphicsEndFrame               = uint16(0x000c)
	rdpGraphicsFrameAcknowledge       = uint16(0x000d)
	RDPGraphicsResetGraphics          = uint16(0x000e)
	RDPGraphicsMapSurfaceToOutput     = uint16(0x000f)
	rdpGraphicsCacheImportOffer       = uint16(0x0010)
	RDPGraphicsCacheImportReply       = uint16(0x0011)
	rdpGraphicsCapsAdvertise          = uint16(0x0012)
	rdpGraphicsCapsConfirm            = uint16(0x0013)
	RDPGraphicsMapSurfaceToWindow     = uint16(0x0015)
	rdpGraphicsQoEFrameAcknowledge    = uint16(0x0016)
	RDPGraphicsMapSurfaceToScaledOut  = uint16(0x0017)
	RDPGraphicsMapSurfaceToScaledWind = uint16(0x0018)

	rdpGraphicsHeaderSize = 8
)

// rdpGraphicsFromTarget are the commands a target sends after its confirmation. The others go from
// the client (frame and QoE acknowledgements, cache import offer, capabilities), or are not defined.
var rdpGraphicsFromTarget = map[uint16]bool{
	RDPGraphicsWireToSurface1: true, RDPGraphicsWireToSurface2: true, RDPGraphicsDeleteEncodingContext: true,
	RDPGraphicsSolidFill: true, RDPGraphicsSurfaceToSurface: true, RDPGraphicsSurfaceToCache: true,
	RDPGraphicsCacheToSurface: true, RDPGraphicsEvictCacheEntry: true, RDPGraphicsCreateSurface: true,
	RDPGraphicsDeleteSurface: true, RDPGraphicsStartFrame: true, RDPGraphicsEndFrame: true,
	RDPGraphicsResetGraphics: true, RDPGraphicsMapSurfaceToOutput: true, RDPGraphicsCacheImportReply: true,
	RDPGraphicsMapSurfaceToWindow: true, RDPGraphicsMapSurfaceToScaledOut: true, RDPGraphicsMapSurfaceToScaledWind: true,
}

// The capability versions and flags (MS-RDPEGFX 2.2.3).
const (
	rdpGraphicsCapVersion8   = uint32(0x00080004)
	rdpGraphicsCapVersion81  = uint32(0x00080105)
	rdpGraphicsCapVersion10  = uint32(0x000a0002)
	rdpGraphicsCapVersion102 = uint32(0x000a0200)
	rdpGraphicsCapVersion104 = uint32(0x000a0400)
	rdpGraphicsCapVersion105 = uint32(0x000a0502)
	rdpGraphicsCapVersion106 = uint32(0x000a0600)
	rdpGraphicsCapVersion107 = uint32(0x000a0701)

	rdpGraphicsCapsSmallCache       = uint32(0x00000002)
	rdpGraphicsCapsAVCDisabled      = uint32(0x00000020)
	rdpGraphicsCapsScaledMapDisable = uint32(0x00000080)
)

// RDPGraphicsCapabilitySet is one RDPGFX_CAPSET whose data is its flags (every version advertised
// here has four bytes of flags).
type RDPGraphicsCapabilitySet struct {
	Version uint32
	Flags   uint32
}

// rdpGraphicsAdvertised are the sets advertised, the newest first. Version 10.1 is not (16 reserved
// bytes and no AVC_DISABLED), nor 10.3 (AVC_DISABLED without SMALL_CACHE: a cache of 100 MB). 8 and
// 8.1 have no AVC unless asked (AVC420_ENABLED, not set).
var rdpGraphicsAdvertised = []RDPGraphicsCapabilitySet{
	{rdpGraphicsCapVersion107, rdpGraphicsCapsAVCDisabled | rdpGraphicsCapsSmallCache | rdpGraphicsCapsScaledMapDisable},
	{rdpGraphicsCapVersion106, rdpGraphicsCapsAVCDisabled | rdpGraphicsCapsSmallCache},
	{rdpGraphicsCapVersion105, rdpGraphicsCapsAVCDisabled | rdpGraphicsCapsSmallCache},
	{rdpGraphicsCapVersion104, rdpGraphicsCapsAVCDisabled | rdpGraphicsCapsSmallCache},
	{rdpGraphicsCapVersion102, rdpGraphicsCapsAVCDisabled | rdpGraphicsCapsSmallCache},
	{rdpGraphicsCapVersion10, rdpGraphicsCapsAVCDisabled | rdpGraphicsCapsSmallCache},
	{rdpGraphicsCapVersion81, rdpGraphicsCapsSmallCache},
	{rdpGraphicsCapVersion8, rdpGraphicsCapsSmallCache},
}

// RDPGraphicsPDU is one PDU of the graphics pipeline: its command and what follows its header.
type RDPGraphicsPDU struct {
	Command uint16
	Body    []byte
}

// RDPGraphicsPipeline reads the graphics channel of one session, from its opening: create one when
// the channel opens (it may open again after a reactivation, with a history of its own), send
// CapsAdvertise, then give it every message of the channel.
type RDPGraphicsPipeline struct {
	zgfx      *zgfxDecompressor
	confirmed *RDPGraphicsCapabilitySet
}

// NewRDPGraphicsPipeline is a pipeline for a channel just opened.
func NewRDPGraphicsPipeline() *RDPGraphicsPipeline {
	return &RDPGraphicsPipeline{zgfx: newZGFXDecompressor()}
}

// CapsAdvertise is the RDPGFX_CAPS_ADVERTISE_PDU (2.2.2.18) to send first on the channel.
func (p *RDPGraphicsPipeline) CapsAdvertise() []byte {
	body := binary.LittleEndian.AppendUint16(nil, uint16(len(rdpGraphicsAdvertised)))
	for _, set := range rdpGraphicsAdvertised {
		body = binary.LittleEndian.AppendUint32(body, set.Version)
		body = binary.LittleEndian.AppendUint32(body, 4)
		body = binary.LittleEndian.AppendUint32(body, set.Flags)
	}
	return marshalGraphicsPDU(rdpGraphicsCapsAdvertise, body)
}

func marshalGraphicsPDU(command uint16, body []byte) []byte {
	out := binary.LittleEndian.AppendUint16(nil, command)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint32(out, uint32(rdpGraphicsHeaderSize+len(body)))
	return append(out, body...)
}

// Confirmed is the capability set the target confirmed, once it has.
func (p *RDPGraphicsPipeline) Confirmed() (RDPGraphicsCapabilitySet, bool) {
	if p == nil || p.confirmed == nil {
		return RDPGraphicsCapabilitySet{}, false
	}
	return *p.confirmed, true
}

// Read decompresses one message of the channel and returns its PDUs, in order, the confirmation
// excepted: it is checked and kept (Confirmed). A message outside MS-RDPEGFX, a PDU before the
// confirmation, a second confirmation, a confirmation of a set not advertised, or a command the
// target does not send, is an error, which ends the session.
func (p *RDPGraphicsPipeline) Read(message []byte) ([]RDPGraphicsPDU, error) {
	if len(message) > maxGraphicsMessage {
		return nil, fmt.Errorf("%w: a %d-byte message", ErrRDPGraphics, len(message))
	}
	data, err := p.zgfx.segmentedData(message)
	if err != nil {
		return nil, err
	}
	var pdus []RDPGraphicsPDU
	for len(data) > 0 {
		if len(data) < rdpGraphicsHeaderSize {
			return nil, fmt.Errorf("%w: a header cut short", ErrRDPGraphics)
		}
		command := binary.LittleEndian.Uint16(data[0:2])
		flags := binary.LittleEndian.Uint16(data[2:4])
		length := binary.LittleEndian.Uint32(data[4:8])
		if flags != 0 || length < rdpGraphicsHeaderSize || uint64(length) > uint64(len(data)) {
			return nil, fmt.Errorf("%w: command 0x%04x, flags 0x%04x, %d bytes of %d", ErrRDPGraphics, command, flags, length, len(data))
		}
		body := data[rdpGraphicsHeaderSize:length]
		data = data[length:]
		if command == rdpGraphicsCapsConfirm {
			if err := p.confirm(body); err != nil {
				return nil, err
			}
			continue
		}
		if p.confirmed == nil {
			return nil, fmt.Errorf("%w: command 0x%04x before the capabilities are confirmed", ErrRDPGraphics, command)
		}
		if !rdpGraphicsFromTarget[command] {
			return nil, fmt.Errorf("%w: command 0x%04x", ErrRDPGraphics, command)
		}
		pdus = append(pdus, RDPGraphicsPDU{Command: command, Body: body})
	}
	return pdus, nil
}

// confirm checks an RDPGFX_CAPS_CONFIRM_PDU (2.2.2.19): one set, of a version advertised, with the
// flags advertised for it, every one: without AVC_DISABLED the target may send H.264, without
// SMALL_CACHE it may fill a cache of 100 MB, without SCALEDMAP_DISABLE send scaled mappings.
func (p *RDPGraphicsPipeline) confirm(body []byte) error {
	if p.confirmed != nil {
		return fmt.Errorf("%w: a second capabilities confirmation", ErrRDPGraphics)
	}
	if len(body) != 12 || binary.LittleEndian.Uint32(body[4:8]) != 4 {
		return fmt.Errorf("%w: a %d-byte capabilities confirmation", ErrRDPGraphics, len(body))
	}
	set := RDPGraphicsCapabilitySet{Version: binary.LittleEndian.Uint32(body[0:4]), Flags: binary.LittleEndian.Uint32(body[8:12])}
	i := slices.IndexFunc(rdpGraphicsAdvertised, func(a RDPGraphicsCapabilitySet) bool { return a.Version == set.Version })
	if i < 0 {
		return fmt.Errorf("%w: version 0x%08x confirmed, not advertised", ErrRDPGraphics, set.Version)
	}
	advertised := rdpGraphicsAdvertised[i].Flags
	if set.Flags != advertised {
		return fmt.Errorf("%w: version 0x%08x confirmed with flags 0x%08x, 0x%08x advertised", ErrRDPGraphics, set.Version, set.Flags, advertised)
	}
	p.confirmed = &set
	return nil
}
