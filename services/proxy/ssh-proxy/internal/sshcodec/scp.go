package sshcodec

// The legacy SCP protocol through the proxy (ADR-0038): `scp -t` (to the target) and `scp -f`
// (from the target). The stream that carries the files is read: each file header is recorded
// before it is relayed, and the file's SHA-256 before the byte that ends its content.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

// SCPCommand is an accepted `scp -t|-f [-r] [-p] [-d] [-v] [-q] <path>`.
type SCPCommand struct {
	Upload bool   // -t: files go to the target
	Path   string // the path on the target
	Line   string // the command as relayed to the target
}

// ParseSCPCommand accepts exactly the legacy scp sink or source, and nothing that a shell on
// the target could read as anything else: the path may hold only letters, digits and
// ._/-+@~, (and no "..").
func ParseSCPCommand(cmd string) (SCPCommand, bool) {
	fields := strings.Fields(cmd)
	if len(fields) < 3 || fields[0] != "scp" {
		return SCPCommand{}, false
	}
	var c SCPCommand
	dir := 0
	for _, f := range fields[1 : len(fields)-1] {
		switch f {
		case "-t":
			c.Upload, dir = true, dir+1
		case "-f":
			dir++
		case "-r", "-p", "-d", "-v", "-q":
		default:
			return SCPCommand{}, false
		}
	}
	p := fields[len(fields)-1]
	if dir != 1 || p == "" || strings.Contains(p, "..") {
		return SCPCommand{}, false
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/-+@~,", r)) {
			return SCPCommand{}, false
		}
	}
	c.Path, c.Line = p, strings.Join(fields, " ")
	return c, true
}

// MaxSCPLine bounds a control line.
const MaxSCPLine = 64 << 10

// scpStream reads the side of an SCP session that carries the files (the client's for -t,
// the target's for -f), recording before relaying.
func scpStream(ctx context.Context, events EventRecorder, cmd SCPCommand, from io.Reader, to io.Writer) error {
	way := map[bool]string{true: "upload", false: "download"}[cmd.Upload]
	in := bufio.NewReaderSize(from, 32<<10)
	var dirs []string
	for {
		line, err := in.ReadSlice('\n')
		if err != nil {
			if err == io.EOF && len(line) == 0 {
				return nil
			}
			if err == bufio.ErrBufferFull {
				return fmt.Errorf("scp: a control line of more than %d bytes", in.Size())
			}
			return err
		}
		if len(line) > MaxSCPLine {
			return fmt.Errorf("scp: a control line of more than %d bytes", MaxSCPLine)
		}
		text := strings.TrimSuffix(string(line), "\n")
		switch {
		case strings.HasPrefix(text, "C"):
			parts := strings.SplitN(text, " ", 3)
			if len(parts) != 3 {
				return fmt.Errorf("scp: a file header that does not read")
			}
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || size < 0 {
				return fmt.Errorf("scp: a file size that does not read")
			}
			name := path.Join(append(append([]string{cmd.Path}, dirs...), parts[2])...)
			if err := events.RecordEvent(ctx, fmt.Sprintf("scp %s %s (%d bytes)", way, q(name), size)); err != nil {
				return err
			}
			if _, err := to.Write(line); err != nil {
				return err
			}
			sum := sha256.New()
			if _, err := io.CopyN(io.MultiWriter(to, sum), in, size); err != nil {
				return err
			}
			end, err := in.ReadByte() // the byte that ends the content
			if err != nil {
				return err
			}
			if err := events.RecordEvent(ctx, fmt.Sprintf("scp %s %s (%d bytes, sha256 %s)", way, q(name), size, hex.EncodeToString(sum.Sum(nil)))); err != nil {
				return err
			}
			if _, err := to.Write([]byte{end}); err != nil {
				return err
			}
			continue
		case strings.HasPrefix(text, "D"):
			parts := strings.SplitN(text, " ", 3)
			if len(parts) != 3 {
				return fmt.Errorf("scp: a directory header that does not read")
			}
			dirs = append(dirs, parts[2])
			if err := events.RecordEvent(ctx, fmt.Sprintf("scp %s directory %s", way, q(path.Join(append([]string{cmd.Path}, dirs...)...)))); err != nil {
				return err
			}
		case text == "E":
			if len(dirs) > 0 {
				dirs = dirs[:len(dirs)-1]
			}
		}
		// T (times), E, an acknowledgement byte run, or anything else: relayed as it is.
		if _, err := to.Write(line); err != nil {
			return err
		}
	}
}
