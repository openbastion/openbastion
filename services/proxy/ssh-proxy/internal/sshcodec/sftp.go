package sshcodec

// SFTP through the proxy (ADR-0038): the protocol (version 3) is read in both directions, and
// every file opened, every change, and every file closed — with its size and SHA-256 — is
// recorded and acknowledged BEFORE the packet that causes it is relayed.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"sync"
)

// EventRecorder records one event of a session before it is relayed (proxycore.RecordingTap):
// an error means the event was not acknowledged, and the session must end.
type EventRecorder interface {
	RecordEvent(ctx context.Context, event string) error
}

// MaxSFTPPacket bounds an SFTP packet: OpenSSH uses at most 256 KiB.
const MaxSFTPPacket = 1 << 20

const (
	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpSetstat  = 9
	fxpFsetstat = 10
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRename   = 18
	fxpSymlink  = 20
	fxpStatus   = 101
	fxpHandle   = 102
	fxpData     = 103
	fxpExtended = 200

	fxfRead  = 0x1
	fxfWrite = 0x2
)

var errBadPacket = errors.New("sftp: a packet that does not read")

// direction is the bytes of one file in one direction: their SHA-256 while they come in order.
type direction struct {
	used       bool
	next, size int64
	sum        hash.Hash
	sequential bool
}

func newDirection() *direction { return &direction{sum: sha256.New(), sequential: true} }

func (d *direction) add(offset int64, data []byte) {
	d.used = true
	if end := offset + int64(len(data)); end > d.size {
		d.size = end
	}
	if d.sequential && offset == d.next {
		d.sum.Write(data)
		d.next += int64(len(data))
	} else {
		d.sequential = false
	}
}

func (d *direction) summary() string {
	if !d.sequential || d.next != d.size {
		return fmt.Sprintf("%d bytes, sha256 not computed: non-sequential", d.size)
	}
	return fmt.Sprintf("%d bytes, sha256 %s", d.size, hex.EncodeToString(d.sum.Sum(nil)))
}

type sftpFile struct {
	path            string
	reading, writes bool
	up, down        *direction
}

type pendingRead struct {
	handle string
	offset int64
}

// sftpWatch is the state shared by the two directions of one SFTP session.
type sftpWatch struct {
	events EventRecorder

	mu      sync.Mutex
	opening map[uint32]*sftpFile // request id -> file being opened
	files   map[string]*sftpFile // handle -> open file
	reads   map[uint32]pendingRead
}

func newSFTPWatch(events EventRecorder) *sftpWatch {
	return &sftpWatch{events: events, opening: map[uint32]*sftpFile{}, files: map[string]*sftpFile{}, reads: map[uint32]pendingRead{}}
}

// readPacket reads one length-prefixed packet, whole.
func readPacket(r io.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n == 0 || n > MaxSFTPPacket {
		return nil, fmt.Errorf("sftp: a packet of %d bytes (at most %d)", n, MaxSFTPPacket)
	}
	p := make([]byte, 4+n)
	copy(p, l[:])
	if _, err := io.ReadFull(r, p[4:]); err != nil {
		return nil, err
	}
	return p, nil
}

// reader walks the fields of a packet body.
type reader struct {
	b   []byte
	err error
}

func (r *reader) uint32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errBadPacket
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) uint64() uint64 {
	if r.err != nil || len(r.b) < 8 {
		r.err = errBadPacket
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *reader) bytes() []byte {
	n := r.uint32()
	if r.err != nil || uint64(len(r.b)) < uint64(n) {
		r.err = errBadPacket
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) string() string { return string(r.bytes()) }

// q writes a path so that no name can forge a line of the recording.
func q(s string) string { return strconv.Quote(s) }

// clientToTarget relays the client's requests, recording what must be recorded first.
func (w *sftpWatch) clientToTarget(ctx context.Context, from io.Reader, to io.Writer) error {
	for {
		p, err := readPacket(from)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := w.request(ctx, p); err != nil {
			return err
		}
		if _, err := to.Write(p); err != nil {
			return err
		}
	}
}

func (w *sftpWatch) request(ctx context.Context, p []byte) error {
	typ := p[4]
	if typ == fxpInit {
		return nil
	}
	r := &reader{b: p[5:]}
	id := r.uint32()
	var event string
	switch typ {
	case fxpOpen:
		path := r.string()
		flags := r.uint32()
		if r.err != nil {
			return r.err
		}
		f := &sftpFile{path: path, reading: flags&fxfRead != 0, writes: flags&fxfWrite != 0, up: newDirection(), down: newDirection()}
		mode := map[[2]bool]string{{true, false}: "reading", {false, true}: "writing", {true, true}: "reading and writing", {false, false}: "nothing"}[[2]bool{f.reading, f.writes}]
		event = fmt.Sprintf("sftp open %s for %s", q(path), mode)
		w.mu.Lock()
		w.opening[id] = f
		w.mu.Unlock()
	case fxpWrite:
		handle := r.string()
		offset := r.uint64()
		data := r.bytes()
		if r.err != nil {
			return r.err
		}
		w.mu.Lock()
		if f := w.files[handle]; f != nil {
			f.up.add(int64(offset), data)
		}
		w.mu.Unlock()
		return nil
	case fxpRead:
		handle := r.string()
		offset := r.uint64()
		if r.err != nil {
			return r.err
		}
		w.mu.Lock()
		w.reads[id] = pendingRead{handle: handle, offset: int64(offset)}
		w.mu.Unlock()
		return nil
	case fxpClose:
		handle := r.string()
		if r.err != nil {
			return r.err
		}
		w.mu.Lock()
		f := w.files[handle]
		delete(w.files, handle)
		w.mu.Unlock()
		if f == nil {
			return nil // a directory, or a handle this proxy never saw opened
		}
		if f.writes || f.up.used {
			if err := w.events.RecordEvent(ctx, fmt.Sprintf("sftp upload %s (%s)", q(f.path), f.up.summary())); err != nil {
				return err
			}
		}
		if f.down.used || (f.reading && !f.writes) {
			event = fmt.Sprintf("sftp download %s (%s)", q(f.path), f.down.summary())
		}
	case fxpSetstat:
		event = "sftp setstat " + q(r.string())
	case fxpFsetstat:
		handle := r.string()
		w.mu.Lock()
		path := handle
		if f := w.files[handle]; f != nil {
			path = f.path
		}
		w.mu.Unlock()
		event = "sftp setstat " + q(path)
	case fxpRemove:
		event = "sftp remove " + q(r.string())
	case fxpMkdir:
		event = "sftp mkdir " + q(r.string())
	case fxpRmdir:
		event = "sftp rmdir " + q(r.string())
	case fxpRename:
		from := r.string()
		event = fmt.Sprintf("sftp rename %s -> %s", q(from), q(r.string()))
	case fxpSymlink:
		a := r.string()
		event = fmt.Sprintf("sftp symlink %s %s", q(a), q(r.string()))
	case fxpExtended:
		name := r.string()
		switch name {
		case "posix-rename@openssh.com":
			from := r.string()
			event = fmt.Sprintf("sftp rename %s -> %s", q(from), q(r.string()))
		case "hardlink@openssh.com":
			from := r.string()
			event = fmt.Sprintf("sftp hardlink %s -> %s", q(from), q(r.string()))
		case "statvfs@openssh.com", "fstatvfs@openssh.com", "limits@openssh.com", "expand-path@openssh.com", "home-directory":
			return r.err // reads of metadata
		default:
			event = "sftp extended " + q(name)
		}
	default:
		return r.err // reads of metadata: stat, lstat, fstat, opendir, readdir, realpath, readlink
	}
	if r.err != nil {
		return r.err
	}
	if event == "" {
		return nil
	}
	return w.events.RecordEvent(ctx, event)
}

// targetToClient relays the target's answers, learning the handles of opened files and the
// bytes read from them.
func (w *sftpWatch) targetToClient(from io.Reader, to io.Writer) error {
	for {
		p, err := readPacket(from)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := w.answer(p); err != nil {
			return err
		}
		if _, err := to.Write(p); err != nil {
			return err
		}
	}
}

func (w *sftpWatch) answer(p []byte) error {
	typ := p[4]
	if typ == fxpVersion {
		return nil
	}
	r := &reader{b: p[5:]}
	id := r.uint32()
	w.mu.Lock()
	defer w.mu.Unlock()
	switch typ {
	case fxpHandle:
		handle := r.string()
		if f := w.opening[id]; f != nil {
			w.files[handle] = f
			delete(w.opening, id)
		}
	case fxpData:
		data := r.bytes()
		if pr, ok := w.reads[id]; ok {
			delete(w.reads, id)
			if f := w.files[pr.handle]; f != nil {
				f.down.add(pr.offset, data)
			}
		}
	case fxpStatus:
		delete(w.opening, id) // an open that failed
		delete(w.reads, id)   // a read at the end of the file
	}
	return r.err
}
