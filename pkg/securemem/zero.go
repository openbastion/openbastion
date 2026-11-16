// Package securemem contains best-effort primitives for shortening the lifetime of secret bytes.
// It does not provide locked, non-swappable, or garbage-collector-independent memory.
package securemem

import "runtime"

// Zero overwrites every byte in b and keeps the backing array live until the writes have completed.
// Callers must still avoid creating copies: Go strings, compiler temporaries, the GC, and libraries
// may retain other representations that this function cannot reach.
func Zero(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
