package sshcodec

// SFTP and SCP through the proxy (ADR-0038): every transfer recorded before it is relayed.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

// journal is both sides of the relay: what was recorded and what was relayed, in order.
type journal struct {
	mu      sync.Mutex
	log     []string
	refuse  string // an event containing this is refused
	relayed bytes.Buffer
}

func (j *journal) RecordEvent(_ context.Context, e string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.refuse != "" && strings.Contains(e, j.refuse) {
		return errors.New("recorder down")
	}
	j.log = append(j.log, "event: "+e)
	return nil
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.relayed.Write(p)
	if len(p) > 4 {
		j.log = append(j.log, "relay: type "+itoa(int(p[4])))
	}
	return len(p), nil
}

func itoa(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+n/100)) + string(rune('0'+n/10%10)) + string(rune('0'+n%10))) }

// pkt builds an SFTP packet: type, id (unless 0 for INIT/VERSION), then fields.
func pkt(typ byte, id uint32, fields ...any) []byte {
	var body bytes.Buffer
	body.WriteByte(typ)
	if typ != fxpInit && typ != fxpVersion {
		_ = binary.Write(&body, binary.BigEndian, id)
	}
	for _, f := range fields {
		switch v := f.(type) {
		case string:
			_ = binary.Write(&body, binary.BigEndian, uint32(len(v)))
			body.WriteString(v)
		case []byte:
			_ = binary.Write(&body, binary.BigEndian, uint32(len(v)))
			body.Write(v)
		case uint32:
			_ = binary.Write(&body, binary.BigEndian, v)
		case uint64:
			_ = binary.Write(&body, binary.BigEndian, v)
		}
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(body.Len()))
	return append(out, body.Bytes()...)
}

func run(t *testing.T, w *sftpWatch, j *journal, toTarget [][]byte, toClient [][]byte) error {
	t.Helper()
	// The two directions interleave as on the wire: each answer after its request.
	var err error
	for i, p := range toTarget {
		if err = w.clientToTarget(context.Background(), bytes.NewReader(p), j); err != nil {
			return err
		}
		if i < len(toClient) && toClient[i] != nil {
			if err := w.targetToClient(bytes.NewReader(toClient[i]), &bytes.Buffer{}); err != nil {
				return err
			}
		}
	}
	return nil
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestSFTP_AnUploadIsRecordedBeforeItsOpenAndItsCloseAreRelayed(t *testing.T) {
	j := &journal{}
	w := newSFTPWatch(j)
	err := run(t, w, j,
		[][]byte{pkt(fxpInit, 0, uint32(3)), pkt(fxpOpen, 1, "/srv/a.txt", uint32(fxfWrite|0x08), uint32(0)),
			pkt(fxpWrite, 2, "h1", uint64(0), []byte("hello ")), pkt(fxpWrite, 3, "h1", uint64(6), []byte("world")),
			pkt(fxpClose, 4, "h1")},
		[][]byte{nil, pkt(fxpHandle, 1, "h1"), nil, nil, nil})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"relay: type 001",
		`event: sftp open "/srv/a.txt" for writing`, "relay: type 003",
		"relay: type 006", "relay: type 006",
		`event: sftp upload "/srv/a.txt" (11 bytes, sha256 ` + sha([]byte("hello world")) + ")", "relay: type 004",
	}
	if strings.Join(j.log, "\n") != strings.Join(want, "\n") {
		t.Fatalf("journal:\n%s\nwant:\n%s", strings.Join(j.log, "\n"), strings.Join(want, "\n"))
	}
}

func TestSFTP_ADownloadHashesWhatTheTargetSent(t *testing.T) {
	j := &journal{}
	w := newSFTPWatch(j)
	err := run(t, w, j,
		[][]byte{pkt(fxpOpen, 1, "/etc/shadow", uint32(fxfRead), uint32(0)), pkt(fxpRead, 2, "h9", uint64(0), uint32(4)),
			pkt(fxpRead, 3, "h9", uint64(4), uint32(4)), pkt(fxpRead, 4, "h9", uint64(8), uint32(4)), pkt(fxpClose, 5, "h9")},
		[][]byte{pkt(fxpHandle, 1, "h9"), pkt(fxpData, 2, []byte("root")), pkt(fxpData, 3, []byte(":x:0")), pkt(fxpStatus, 4, uint32(1)), nil})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(j.log, "\n"), `event: sftp download "/etc/shadow" (8 bytes, sha256 `+sha([]byte("root:x:0"))+")") {
		t.Fatalf("journal %v", j.log)
	}
}

func TestSFTP_NonSequentialWritesHaveASizeButNoHash(t *testing.T) {
	j := &journal{}
	w := newSFTPWatch(j)
	_ = run(t, w, j, [][]byte{pkt(fxpOpen, 1, "/x", uint32(fxfWrite), uint32(0)), pkt(fxpWrite, 2, "h", uint64(4), []byte("bbbb")),
		pkt(fxpWrite, 3, "h", uint64(0), []byte("aaaa")), pkt(fxpClose, 4, "h")}, [][]byte{pkt(fxpHandle, 1, "h")})
	if !strings.Contains(strings.Join(j.log, "\n"), `sftp upload "/x" (8 bytes, sha256 not computed: non-sequential)`) {
		t.Fatalf("journal %v", j.log)
	}
}

func TestSFTP_ChangesAreRecorded_MetadataReadsAreNot(t *testing.T) {
	j := &journal{}
	w := newSFTPWatch(j)
	_ = run(t, w, j, [][]byte{
		pkt(fxpRemove, 1, "/a"), pkt(fxpMkdir, 2, "/d", uint32(0)), pkt(fxpRmdir, 3, "/d"), pkt(fxpRename, 4, "/a", "/b"),
		pkt(fxpSetstat, 5, "/b", uint32(0)), pkt(fxpSymlink, 6, "/l", "/b"), pkt(fxpExtended, 7, "posix-rename@openssh.com", "/b", "/c"),
		pkt(fxpExtended, 8, "hardlink@openssh.com", "/c", "/h"), pkt(fxpExtended, 9, "copy-data", "x"),
		pkt(17, 10, "/c"), pkt(16, 11, "."), pkt(11, 12, "/"), pkt(fxpExtended, 13, "statvfs@openssh.com", "/"),
	}, nil)
	var events []string
	for _, l := range j.log {
		if strings.HasPrefix(l, "event: ") {
			events = append(events, strings.TrimPrefix(l, "event: "))
		}
	}
	want := []string{`sftp remove "/a"`, `sftp mkdir "/d"`, `sftp rmdir "/d"`, `sftp rename "/a" -> "/b"`, `sftp setstat "/b"`,
		`sftp symlink "/l" "/b"`, `sftp rename "/b" -> "/c"`, `sftp hardlink "/c" -> "/h"`, `sftp extended "copy-data"`}
	if strings.Join(events, "|") != strings.Join(want, "|") {
		t.Fatalf("events %q\nwant %q", events, want)
	}
}

func TestSFTP_ARefusedRecordStopsThePacket_AndTheSession(t *testing.T) {
	for _, refuse := range []string{"open", "upload", "remove"} {
		j := &journal{refuse: refuse}
		w := newSFTPWatch(j)
		packets := [][]byte{pkt(fxpOpen, 1, "/f", uint32(fxfWrite), uint32(0)), pkt(fxpClose, 2, "h")}
		answers := [][]byte{pkt(fxpHandle, 1, "h")}
		if refuse == "remove" {
			packets, answers = [][]byte{pkt(fxpRemove, 1, "/f")}, nil
		}
		err := run(t, w, j, packets, answers)
		if err == nil {
			t.Fatalf("%s refused: the session went on", refuse)
		}
		if refuse != "upload" && j.relayed.Len() != 0 {
			t.Fatalf("%s refused: %d bytes were relayed anyway", refuse, j.relayed.Len())
		}
		if refuse == "upload" && strings.Contains(strings.Join(j.log, "\n"), "relay: type 004") {
			t.Fatal("the close was relayed though its upload was not recorded")
		}
	}
}

func TestSFTP_ANameCannotForgeALine_AndAnOversizedPacketEndsTheSession(t *testing.T) {
	j := &journal{}
	w := newSFTPWatch(j)
	_ = run(t, w, j, [][]byte{pkt(fxpRemove, 1, "/x\nsftp upload \"/etc/passwd\" (0 bytes)")}, nil)
	if len(j.log) == 0 || strings.Contains(j.log[0], "\n") {
		t.Fatalf("a name broke the line: %q", j.log)
	}
	// A whole, well-formed packet one byte over the limit: refused for its size, not its form.
	huge := pkt(fxpWrite, 1, "h", uint64(0), make([]byte, MaxSFTPPacket-21))
	if n := binary.BigEndian.Uint32(huge); n != MaxSFTPPacket+1 {
		t.Fatalf("the test packet is %d bytes, want %d", n, MaxSFTPPacket+1)
	}
	if err := w.clientToTarget(context.Background(), bytes.NewReader(huge), j); err == nil {
		t.Fatal("a packet over the limit was taken")
	}
	if err := w.clientToTarget(context.Background(), bytes.NewReader(pkt(fxpOpen, 1)), j); err == nil {
		t.Fatal("an open that does not read was taken")
	}
}

func TestParseSCPCommand_OnlyTheLegacySinkOrSource_NothingAShellCouldReadOtherwise(t *testing.T) {
	for _, ok := range []string{"scp -t /tmp/x", "scp -f /etc/hosts", "scp -r -t /srv/dir", "scp -v -p -d -t ~/in", "scp -q -f a,b.tar.gz"} {
		if _, accepted := ParseSCPCommand(ok); !accepted {
			t.Fatalf("%q refused", ok)
		}
	}
	for _, bad := range []string{"scp -t /tmp;rm -rf /", "scp -t /tmp/$(id)", "scp -t /a /b", "scp -t -f /x", "scp /x", "ls -la",
		"scp -t `id`", "scp -t /a|b", "scp -t ../etc", "scp -o ProxyCommand=x -t /a", "rsync --server .", "scp -t /x&&id", "scp -t"} {
		if _, accepted := ParseSCPCommand(bad); accepted {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestSCP_EachFileIsRecordedBeforeItsHeaderAndBeforeItsEnd(t *testing.T) {
	j := &journal{}
	cmd, _ := ParseSCPCommand("scp -r -t /srv")
	stream := "D0755 0 conf\nC0644 5 a.txt\nhello\x00E\nC0600 3 b\nabc\x00"
	var out bytes.Buffer
	order := &orderWriter{j: j, w: &out}
	if err := scpStream(context.Background(), j, cmd, strings.NewReader(stream), order); err != nil {
		t.Fatal(err)
	}
	if out.String() != stream {
		t.Fatalf("relayed %q, want the stream unchanged", out.String())
	}
	got := strings.Join(j.log, "\n")
	want := strings.Join([]string{
		`event: scp upload directory "conf" into "/srv"`, "relay: D0755 0 conf\n",
		`event: scp upload "conf/a.txt" into "/srv" (5 bytes)`, "relay: C0644 5 a.txt\n", "relay: hello",
		`event: scp upload "conf/a.txt" into "/srv" (5 bytes, sha256 ` + sha([]byte("hello")) + ")", "relay: \x00", "relay: E\n",
		`event: scp upload "b" into "/srv" (3 bytes)`, "relay: C0600 3 b\n", "relay: abc",
		`event: scp upload "b" into "/srv" (3 bytes, sha256 ` + sha([]byte("abc")) + ")", "relay: \x00",
	}, "\n")
	if got != want {
		t.Fatalf("journal:\n%q\nwant:\n%q", got, want)
	}
}

func TestSCP_ARefusedRecordStopsTheFile(t *testing.T) {
	j := &journal{refuse: "(5 bytes)"}
	cmd, _ := ParseSCPCommand("scp -t /srv")
	var out bytes.Buffer
	if err := scpStream(context.Background(), j, cmd, strings.NewReader("C0644 5 a\nhello\x00"), &out); err == nil {
		t.Fatal("the file went on")
	}
	if out.Len() != 0 {
		t.Fatalf("relayed %q though the header was not recorded", out.String())
	}
}

// orderWriter records each relayed chunk in the journal, to check the order of events and data.
type orderWriter struct {
	j *journal
	w *bytes.Buffer
}

func (o *orderWriter) Write(p []byte) (int, error) {
	o.j.mu.Lock()
	o.j.log = append(o.j.log, "relay: "+string(p))
	o.j.mu.Unlock()
	return o.w.Write(p)
}
