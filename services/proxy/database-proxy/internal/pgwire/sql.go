package pgwire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrCopyUnsupported       = errors.New("postgresql COPY is not supported by this proxy release")
	ErrInvalidQueryMessage   = errors.New("malformed postgresql query message")
	ErrInvalidFingerprintKey = errors.New("invalid per-session query fingerprint key")
)

// ParseSimpleQuery validates a simple-query frontend message and refuses COPY
// before any bytes of its payload reach the target.
func ParseSimpleQuery(message FrontendMessage) (string, error) {
	if message.Type != 'Q' || len(message.Payload) == 0 || message.Payload[len(message.Payload)-1] != 0 {
		return "", ErrInvalidQueryMessage
	}
	for _, b := range message.Payload[:len(message.Payload)-1] {
		if b == 0 {
			return "", ErrInvalidQueryMessage
		}
	}
	query := string(message.Payload[:len(message.Payload)-1])
	if firstSQLKeyword(query) == "COPY" {
		return "", ErrCopyUnsupported
	}
	return query, nil
}

// FingerprintSQL returns a per-session HMAC-SHA-256 over normalized SQL. The
// query text and literals never leave process memory or enter the recording.
func FingerprintSQL(sessionKey []byte, query string) (string, error) {
	if len(sessionKey) != sha256.Size {
		return "", ErrInvalidFingerprintKey
	}
	normalized := normalizeSQL(query)
	mac := hmac.New(sha256.New, sessionKey)
	_, _ = mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func firstSQLKeyword(query string) string {
	i := skipSQLTrivia(query, 0)
	start := i
	for i < len(query) {
		b := query[i]
		if !(b >= 'a' && b <= 'z') && !(b >= 'A' && b <= 'Z') && b != '_' {
			break
		}
		i++
	}
	if i == start {
		return ""
	}
	return strings.ToUpper(query[start:i])
}

func skipSQLTrivia(query string, offset int) int {
	for offset < len(query) {
		switch {
		case query[offset] == ' ' || query[offset] == '\t' || query[offset] == '\r' || query[offset] == '\n':
			offset++
		case offset+1 < len(query) && query[offset:offset+2] == "--":
			offset += 2
			for offset < len(query) && query[offset] != '\n' {
				offset++
			}
		case offset+1 < len(query) && query[offset:offset+2] == "/*":
			offset = skipBlockComment(query, offset)
		default:
			return offset
		}
	}
	return offset
}

func normalizeSQL(query string) string {
	var out strings.Builder
	pendingSpace := false
	for i := 0; i < len(query); {
		switch {
		case isSQLSpace(query[i]):
			pendingSpace = true
			i++
		case i+1 < len(query) && query[i:i+2] == "--":
			i += 2
			for i < len(query) && query[i] != '\n' {
				i++
			}
			pendingSpace = true
		case i+1 < len(query) && query[i:i+2] == "/*":
			i = skipBlockComment(query, i)
			pendingSpace = true
		case query[i] == '\'' || query[i] == '"':
			writePendingSpace(&out, &pendingSpace)
			i = copyQuoted(&out, query, i, query[i])
		case query[i] == '$':
			if end, ok := dollarQuoteEnd(query, i); ok {
				writePendingSpace(&out, &pendingSpace)
				out.WriteString(query[i:end])
				i = end
			} else {
				writePendingSpace(&out, &pendingSpace)
				out.WriteByte(query[i])
				i++
			}
		default:
			writePendingSpace(&out, &pendingSpace)
			out.WriteByte(query[i])
			i++
		}
	}
	return strings.TrimSpace(out.String())
}

func isSQLSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' }

func writePendingSpace(out *strings.Builder, pending *bool) {
	if *pending && out.Len() > 0 {
		out.WriteByte(' ')
	}
	*pending = false
}

func copyQuoted(out *strings.Builder, query string, offset int, quote byte) int {
	out.WriteByte(quote)
	i := offset + 1
	for i < len(query) {
		out.WriteByte(query[i])
		if query[i] == quote {
			if i+1 < len(query) && query[i+1] == quote {
				out.WriteByte(query[i+1])
				i += 2
				continue
			}
			return i + 1
		}
		if query[i] == '\\' && quote == '\'' && i+1 < len(query) {
			out.WriteByte(query[i+1])
			i += 2
			continue
		}
		i++
	}
	return i
}

func dollarQuoteEnd(query string, offset int) (int, bool) {
	endTag := offset + 1
	for endTag < len(query) && (query[endTag] == '_' || query[endTag] >= 'a' && query[endTag] <= 'z' || query[endTag] >= 'A' && query[endTag] <= 'Z' || query[endTag] >= '0' && query[endTag] <= '9') {
		endTag++
	}
	if endTag >= len(query) || query[endTag] != '$' {
		return 0, false
	}
	tag := query[offset : endTag+1]
	closeAt := strings.Index(query[endTag+1:], tag)
	if closeAt < 0 {
		return len(query), true
	}
	return endTag + 1 + closeAt + len(tag), true
}

func skipBlockComment(query string, offset int) int {
	depth := 1
	for i := offset + 2; i < len(query); {
		switch {
		case i+1 < len(query) && query[i:i+2] == "/*":
			depth++
			i += 2
		case i+1 < len(query) && query[i:i+2] == "*/":
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(query)
}
