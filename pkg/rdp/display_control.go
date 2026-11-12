package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The display control (MS-RDPEDISP), the one dynamic channel of ADR-0095: the target states what
// it accepts (DISPLAYCONTROL_CAPS_PDU), and the client asks for a layout (one monitor, primary, at
// the origin) within it. The target then reactivates at the new size (MS-RDPBCGR 1.3.1.3), which
// the reader already follows.

const (
	displayControlCapsType   = uint32(0x00000005)
	displayControlLayoutType = uint32(0x00000002)
	displayControlCapsLength = 20

	displayControlMonitorSize    = 40
	displayControlMonitorPrimary = uint32(0x00000001)

	// The size a monitor may have (MS-RDPEDISP 2.2.2.2.1): 200 to 8192, the width even.
	displayControlMinSide = 200
	displayControlMaxSide = 8192
)

// ErrRDPDisplayControl reports a display control message outside MS-RDPEDISP, or a layout this
// client will not ask for.
var ErrRDPDisplayControl = errors.New("rdp: display control refused")

// RDPDisplayControlCaps is what the target accepts: monitors, and the largest area of each.
type RDPDisplayControlCaps struct {
	MaxNumMonitors        uint32
	MaxMonitorAreaFactorA uint32
	MaxMonitorAreaFactorB uint32
}

// ParseDisplayControlCaps reads a DISPLAYCONTROL_CAPS_PDU, the only message the target sends on the
// display control.
func ParseDisplayControlCaps(message []byte) (RDPDisplayControlCaps, error) {
	if len(message) != displayControlCapsLength ||
		binary.LittleEndian.Uint32(message[:4]) != displayControlCapsType ||
		binary.LittleEndian.Uint32(message[4:8]) != displayControlCapsLength {
		return RDPDisplayControlCaps{}, fmt.Errorf("%w: not a DISPLAYCONTROL_CAPS_PDU", ErrRDPDisplayControl)
	}
	caps := RDPDisplayControlCaps{
		MaxNumMonitors:        binary.LittleEndian.Uint32(message[8:12]),
		MaxMonitorAreaFactorA: binary.LittleEndian.Uint32(message[12:16]),
		MaxMonitorAreaFactorB: binary.LittleEndian.Uint32(message[16:20]),
	}
	if caps.MaxNumMonitors == 0 || caps.MaxMonitorAreaFactorA == 0 || caps.MaxMonitorAreaFactorB == 0 {
		return RDPDisplayControlCaps{}, fmt.Errorf("%w: capabilities %+v", ErrRDPDisplayControl, caps)
	}
	return caps, nil
}

// Fits says whether one monitor of width x height is within what the target accepts.
func (c RDPDisplayControlCaps) Fits(width, height uint32) bool {
	return c.MaxNumMonitors >= 1 && uint64(width)*uint64(height) <= uint64(c.MaxMonitorAreaFactorA)*uint64(c.MaxMonitorAreaFactorB)
}

// MarshalDisplayControlLayout writes a DISPLAYCONTROL_MONITOR_LAYOUT_PDU for one monitor, primary,
// at the origin, of width x height: no physical size, no orientation, a scale of 100 %.
func MarshalDisplayControlLayout(width, height uint32) ([]byte, error) {
	if width < displayControlMinSide || width > displayControlMaxSide || width%2 != 0 ||
		height < displayControlMinSide || height > displayControlMaxSide {
		return nil, fmt.Errorf("%w: a %d x %d monitor", ErrRDPDisplayControl, width, height)
	}
	out := make([]byte, 16+displayControlMonitorSize)
	binary.LittleEndian.PutUint32(out[0:4], displayControlLayoutType)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[8:12], displayControlMonitorSize)
	binary.LittleEndian.PutUint32(out[12:16], 1)
	monitor := out[16:]
	binary.LittleEndian.PutUint32(monitor[0:4], displayControlMonitorPrimary)
	// Left and Top are 0: the primary monitor is at the origin.
	binary.LittleEndian.PutUint32(monitor[12:16], width)
	binary.LittleEndian.PutUint32(monitor[16:20], height)
	// PhysicalWidth, PhysicalHeight and Orientation are 0: unknown, landscape.
	binary.LittleEndian.PutUint32(monitor[32:36], 100) // DesktopScaleFactor
	binary.LittleEndian.PutUint32(monitor[36:40], 100) // DeviceScaleFactor
	return out, nil
}
