package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// The clipboard (MS-RDPECLIP), on the static channel cliprdr (ADR-0096): text only, CF_UNICODETEXT,
// in each direction the session allows. No long format names, no files, no locking are announced;
// a message about them is outside the protocol this client speaks, and ends the session. Every
// other format the target offers is passed over; a request for one is answered with a failure.

// RDPChannelClipboard is the static channel of the clipboard.
const RDPChannelClipboard = "cliprdr"

const (
	cbMonitorReady       = uint16(0x0001)
	cbFormatList         = uint16(0x0002)
	cbFormatListResponse = uint16(0x0003)
	cbFormatDataRequest  = uint16(0x0004)
	cbFormatDataResponse = uint16(0x0005)
	cbClipCaps           = uint16(0x0007)

	cbResponseOK   = uint16(0x0001)
	cbResponseFail = uint16(0x0002)
	cbASCIINames   = uint16(0x0004)

	cbCapsGeneral   = uint16(0x0001)
	cbCapsVersion2  = uint32(0x00000002)
	cbShortNameSize = 32

	// cfUnicodeText is CF_UNICODETEXT: UTF-16LE, terminated by a NUL.
	cfUnicodeText = uint32(13)

	// MaxRDPClipboardTextBytes bounds a text in either direction (ADR-0096 §3): its UTF-16 bytes,
	// NUL excluded, so that the data response, its header and its NUL fit a channel message.
	MaxRDPClipboardTextBytes = MaxRDPChannelMessage - 8 - 2
)

// ErrRDPClipboard reports a clipboard message outside MS-RDPECLIP, its bounds, or this client's
// profile of it.
var ErrRDPClipboard = errors.New("rdp: clipboard message refused")

// rdpClipboard is the clipboard of one session: what the target said, what the operator offers it,
// and what is asked of the target.
type rdpClipboard struct {
	toTarget, fromTarget bool
	capsSeen, ready      bool
	// offered is the text offered to the target, as UTF-16LE with its NUL, until it asks for it.
	offered []byte
	// requested says a text was asked of the target and its response is awaited.
	requested bool
	// What handle found to tell, told by the reader once s.mu is released and the answers sent.
	offers int
	texts  []string
}

func clipboardMessage(msgType, flags uint16, data []byte) []byte {
	out := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(out[0:2], msgType)
	binary.LittleEndian.PutUint16(out[2:4], flags)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(data)))
	copy(out[8:], data)
	return out
}

// clientCapabilities is the CB_CLIP_CAPS this client sends: version 2, no general flag (short
// format names, no file stream, no locking).
func clientCapabilities() []byte {
	data := make([]byte, 4+12)
	binary.LittleEndian.PutUint16(data[0:2], 1) // cCapabilitiesSets
	binary.LittleEndian.PutUint16(data[4:6], cbCapsGeneral)
	binary.LittleEndian.PutUint16(data[6:8], 12)
	binary.LittleEndian.PutUint32(data[8:12], cbCapsVersion2)
	return clipboardMessage(cbClipCaps, 0, data)
}

// formatList is a CB_FORMAT_LIST of short names: CF_UNICODETEXT alone when text is offered, none
// otherwise.
func formatList(withText bool) []byte {
	if !withText {
		return clipboardMessage(cbFormatList, 0, nil)
	}
	entry := make([]byte, 4+cbShortNameSize)
	binary.LittleEndian.PutUint32(entry[:4], cfUnicodeText)
	return clipboardMessage(cbFormatList, 0, entry)
}

// handle reads one cliprdr message and returns the answers to send back, in order.
func (c *rdpClipboard) handle(message []byte) ([][]byte, error) {
	if len(message) < 8 {
		return nil, fmt.Errorf("%w: a message shorter than its header", ErrRDPClipboard)
	}
	msgType := binary.LittleEndian.Uint16(message[0:2])
	flags := binary.LittleEndian.Uint16(message[2:4])
	data := message[8:]
	if int(binary.LittleEndian.Uint32(message[4:8])) != len(data) {
		return nil, fmt.Errorf("%w: dataLen says %d, the message carries %d", ErrRDPClipboard, binary.LittleEndian.Uint32(message[4:8]), len(data))
	}
	switch msgType {
	case cbClipCaps:
		if c.capsSeen || c.ready || flags != 0 || len(data) < 4 {
			return nil, fmt.Errorf("%w: capabilities out of order or malformed", ErrRDPClipboard)
		}
		count := int(binary.LittleEndian.Uint16(data[0:2]))
		sets := data[4:]
		for i := 0; i < count; i++ {
			if len(sets) < 4 {
				return nil, fmt.Errorf("%w: a capability set cut short", ErrRDPClipboard)
			}
			length := int(binary.LittleEndian.Uint16(sets[2:4]))
			if length < 4 || length > len(sets) {
				return nil, fmt.Errorf("%w: a capability set of %d bytes", ErrRDPClipboard, length)
			}
			sets = sets[length:]
		}
		if len(sets) != 0 {
			return nil, fmt.Errorf("%w: bytes after the capability sets", ErrRDPClipboard)
		}
		c.capsSeen = true
		return nil, nil
	case cbMonitorReady:
		if c.ready || flags != 0 || len(data) != 0 {
			return nil, fmt.Errorf("%w: monitor ready out of order or malformed", ErrRDPClipboard)
		}
		c.ready = true
		// The client's capabilities, then its format list: the text offered, if any.
		return [][]byte{clientCapabilities(), formatList(c.toTarget && c.offered != nil)}, nil
	}
	if !c.ready {
		return nil, fmt.Errorf("%w: message %d before monitor ready", ErrRDPClipboard, msgType)
	}
	switch msgType {
	case cbFormatList:
		// Short names: each entry is a format ID and 32 bytes of name; only the ID matters here.
		if flags&^cbASCIINames != 0 || len(data)%(4+cbShortNameSize) != 0 {
			return nil, fmt.Errorf("%w: a format list of %d bytes, flags 0x%04x", ErrRDPClipboard, len(data), flags)
		}
		hasText := false
		for at := 0; at < len(data); at += 4 + cbShortNameSize {
			if binary.LittleEndian.Uint32(data[at:at+4]) == cfUnicodeText {
				hasText = true
			}
		}
		if hasText && c.fromTarget {
			c.offers++
		}
		return [][]byte{clipboardMessage(cbFormatListResponse, cbResponseOK, nil)}, nil
	case cbFormatListResponse:
		if (flags != cbResponseOK && flags != cbResponseFail) || len(data) != 0 {
			return nil, fmt.Errorf("%w: a format list response flagged 0x%04x", ErrRDPClipboard, flags)
		}
		return nil, nil
	case cbFormatDataRequest:
		if flags != 0 || len(data) != 4 {
			return nil, fmt.Errorf("%w: a malformed data request", ErrRDPClipboard)
		}
		if binary.LittleEndian.Uint32(data) != cfUnicodeText || !c.toTarget || c.offered == nil {
			return [][]byte{clipboardMessage(cbFormatDataResponse, cbResponseFail, nil)}, nil
		}
		answer := clipboardMessage(cbFormatDataResponse, cbResponseOK, c.offered)
		return [][]byte{answer}, nil
	case cbFormatDataResponse:
		if !c.requested {
			return nil, fmt.Errorf("%w: a data response to no request", ErrRDPClipboard)
		}
		c.requested = false
		if flags == cbResponseFail && len(data) == 0 {
			return nil, nil // the target no longer has the text
		}
		if flags != cbResponseOK {
			return nil, fmt.Errorf("%w: a data response flagged 0x%04x", ErrRDPClipboard, flags)
		}
		text, err := decodeClipboardText(data)
		if err != nil {
			return nil, err
		}
		c.texts = append(c.texts, text)
		return nil, nil
	}
	// Temporary directory, file contents, locking: none is announced.
	return nil, fmt.Errorf("%w: message type %d", ErrRDPClipboard, msgType)
}

// decodeClipboardText reads a CF_UNICODETEXT: UTF-16LE, ended by a NUL, within the bound, and
// returns it without its NUL. What follows the first NUL is not text and is not kept.
func decodeClipboardText(data []byte) (string, error) {
	if len(data)%2 != 0 || len(data) < 2 || len(data) > MaxRDPClipboardTextBytes+2 {
		return "", fmt.Errorf("%w: a text of %d bytes", ErrRDPClipboard, len(data))
	}
	units := make([]uint16, 0, len(data)/2)
	for at := 0; at < len(data); at += 2 {
		unit := binary.LittleEndian.Uint16(data[at : at+2])
		if unit == 0 {
			return string(utf16.Decode(units)), nil
		}
		units = append(units, unit)
	}
	return "", fmt.Errorf("%w: a text with no NUL", ErrRDPClipboard)
}

// encodeClipboardText writes text as CF_UNICODETEXT, within the bound.
func encodeClipboardText(text string) ([]byte, error) {
	if !utf8.ValidString(text) {
		return nil, fmt.Errorf("%w: a text that is not UTF-8", ErrRDPClipboard)
	}
	units := utf16.Encode([]rune(text))
	if len(units)*2 > MaxRDPClipboardTextBytes {
		return nil, fmt.Errorf("%w: a text of %d bytes, past %d", ErrRDPClipboard, len(units)*2, MaxRDPClipboardTextBytes)
	}
	out := make([]byte, 0, len(units)*2+2)
	for _, unit := range units {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return append(out, 0, 0), nil
}

func (c *rdpClipboard) take() (int, []string) {
	offers, texts := c.offers, c.texts
	c.offers, c.texts = 0, nil
	return offers, texts
}

// EnableClipboard opens the clipboard of a session whose MCSClientSettings.ClipboardChannel was on
// (ADR-0096): toTarget lets the operator's text be pasted on the target, fromTarget lets the
// target's text be copied. onOffer is told the target has text to copy; onText gets a text copied
// from the target. Both run on the goroutine that reads the screen, after the session's lock is
// released; an error from onText ends the session.
func (s *CredSSPClientSession) EnableClipboard(toTarget, fromTarget bool, onOffer func(), onText func(text string) error) error {
	if s == nil || (!toTarget && !fromTarget) {
		return ErrRDPClipboard
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.mcsSettings.ClipboardChannel || s.clipboard != nil {
		return fmt.Errorf("%w: cliprdr not announced, or the clipboard already enabled", ErrRDPClipboard)
	}
	clipboard := &rdpClipboard{toTarget: toTarget, fromTarget: fromTarget}
	s.clipboard = clipboard
	if s.channelReaders == nil {
		s.channelReaders = map[string]func([]byte) error{}
	}
	s.channelReaders[RDPChannelClipboard] = func(message []byte) error {
		s.mu.Lock()
		answers, err := clipboard.handle(message)
		offers, texts := clipboard.take()
		s.mu.Unlock()
		if err != nil {
			return err
		}
		for _, answer := range answers {
			ctx, cancel := context.WithTimeout(context.Background(), defaultCredSSPTimeout)
			sendErr := s.SendChannelMessage(ctx, RDPChannelClipboard, answer, 0)
			cancel()
			if sendErr != nil {
				return sendErr
			}
		}
		for i := 0; i < offers && onOffer != nil; i++ {
			onOffer()
		}
		for _, text := range texts {
			if onText != nil {
				if err := onText(text); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return nil
}

// OfferClipboardText offers text to the target's clipboard: the target is told a text is there,
// and takes it when an application on it pastes. It replaces what was offered before.
func (s *CredSSPClientSession) OfferClipboardText(ctx context.Context, text string) error {
	encoded, err := encodeClipboardText(text)
	if err != nil {
		return err
	}
	s.mu.Lock()
	clipboard := s.clipboard
	if clipboard == nil || !clipboard.toTarget {
		s.mu.Unlock()
		return fmt.Errorf("%w: pasting on the target is not allowed", ErrRDPClipboard)
	}
	clear(clipboard.offered)
	clipboard.offered = encoded
	ready := clipboard.ready
	s.mu.Unlock()
	if !ready {
		return nil // sent with the format list that follows monitor ready
	}
	return s.SendChannelMessage(ctx, RDPChannelClipboard, formatList(true), 0)
}

// RequestClipboardText asks the target for the text it offered; it comes to onText.
func (s *CredSSPClientSession) RequestClipboardText(ctx context.Context) error {
	s.mu.Lock()
	clipboard := s.clipboard
	if clipboard == nil || !clipboard.fromTarget || !clipboard.ready || clipboard.requested {
		s.mu.Unlock()
		return fmt.Errorf("%w: copying from the target is not allowed now", ErrRDPClipboard)
	}
	clipboard.requested = true
	s.mu.Unlock()
	request := clipboardMessage(cbFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, cfUnicodeText))
	return s.SendChannelMessage(ctx, RDPChannelClipboard, request, 0)
}

// ClipboardReady says the target opened its clipboard (Monitor Ready): before that, nothing can be
// copied, and a text offered waits for it.
func (s *CredSSPClientSession) ClipboardReady() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clipboard != nil && s.clipboard.ready
}
