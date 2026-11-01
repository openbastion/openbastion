package application

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// ChainKeyBytes is the size of a chain key (ADR-0027): 32 random bytes, given as 64 hex digits.
const ChainKeyBytes = 32

// ChainKeys are the keys of the audit chain (ADR-0027): the current one, which signs every
// event written, and previous ones, kept only to verify what they signed. A key is named by
// an identifier derived from it, stored with each event; the key itself is never stored,
// logged or returned.
type ChainKeys struct {
	current string
	keys    map[string][]byte
}

// ErrBadChainKey is returned for a key that is not 32 bytes of hex. Its message never repeats
// the value.
var ErrBadChainKey = errors.New("a chain key must be 64 hexadecimal digits (32 bytes)")

// ParseChainKeys reads the current key and the previous ones (comma-separated) from hex.
func ParseChainKeys(currentHex, previousHex string) (*ChainKeys, error) {
	current, err := decodeChainKey(currentHex)
	if err != nil {
		return nil, fmt.Errorf("current key: %w", err)
	}
	k := &ChainKeys{keys: map[string][]byte{}}
	k.current = k.add(current)
	if strings.TrimSpace(previousHex) != "" {
		for i, p := range strings.Split(previousHex, ",") {
			prev, err := decodeChainKey(p)
			if err != nil {
				return nil, fmt.Errorf("previous key %d: %w", i+1, err)
			}
			k.add(prev)
		}
	}
	return k, nil
}

// RandomChainKeys is a key that lives as long as the process: for a chain that lives as long
// as the process too (in memory), and for a service built by hand.
func RandomChainKeys() *ChainKeys {
	key := make([]byte, ChainKeyBytes)
	if _, err := rand.Read(key); err != nil {
		panic("audit-service: no randomness for a chain key: " + err.Error())
	}
	k := &ChainKeys{keys: map[string][]byte{}}
	k.current = k.add(key)
	return k
}

func decodeChainKey(h string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != ChainKeyBytes {
		return nil, ErrBadChainKey
	}
	return b, nil
}

func (k *ChainKeys) add(key []byte) string {
	id := ChainKeyID(key)
	k.keys[id] = key
	return id
}

// CurrentID names the key that signs new events, for the line written at start-up.
func (k *ChainKeys) CurrentID() string { return k.current }

// Count is how many keys are held, current included.
func (k *ChainKeys) Count() int { return len(k.keys) }

// ChainKeyID names a key without revealing it: the first 8 bytes of a tagged SHA-256 of it.
func ChainKeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("openbastion.audit.chain-key-id\x00"), key...))
	return hex.EncodeToString(sum[:8])
}

// hashV3Tag starts every v3 MAC.
const hashV3Tag = "openbastion.audit.event.v3\x00"

// computeHashV3 (ADR-0027) is an HMAC-SHA256, under the chain key, of v2's framing plus the
// emitter and the key id: without the key, nobody can compute it, so a rewritten tail cannot
// be made to verify.
func computeHashV3(key []byte, e *domain.Event) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(hashV3Tag))
	var n [4]byte
	for _, field := range [][]byte{e.PrevHash, []byte(e.ID), []byte(e.ActorID), []byte(e.Action), []byte(e.ResourceType), []byte(e.ResourceID), []byte(e.Emitter), []byte(e.KeyID)} {
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		m.Write(n[:])
		m.Write(field)
	}
	var successByte [1]byte
	if e.Success {
		successByte[0] = 1
	}
	m.Write(successByte[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.Timestamp.UnixNano()))
	m.Write(tsBuf[:])
	return m.Sum(nil)
}

const hashV4Tag = "openbastion.audit.event.v4\x00"

// computeHashV4 keeps v3's keyed fields and adds details in sorted-key order. The
// count and length prefixes make the map representation unambiguous and stable.
func computeHashV4(key []byte, e *domain.Event) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(hashV4Tag))
	var n [4]byte
	writeField := func(field []byte) {
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		m.Write(n[:])
		m.Write(field)
	}
	for _, field := range [][]byte{e.PrevHash, []byte(e.ID), []byte(e.ActorID), []byte(e.Action), []byte(e.ResourceType), []byte(e.ResourceID), []byte(e.Emitter), []byte(e.KeyID)} {
		writeField(field)
	}
	var successByte [1]byte
	if e.Success {
		successByte[0] = 1
	}
	m.Write(successByte[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.Timestamp.UnixNano()))
	m.Write(tsBuf[:])

	keys := make([]string, 0, len(e.Details))
	for key := range e.Details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	binary.BigEndian.PutUint32(n[:], uint32(len(keys)))
	m.Write(n[:])
	for _, key := range keys {
		writeField([]byte(key))
		writeField([]byte(e.Details[key]))
	}
	return m.Sum(nil)
}
