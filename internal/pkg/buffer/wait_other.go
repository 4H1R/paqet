//go:build !unix

package buffer

// readableWaiter returns a syscall.RawConn.Read callback that completes
// once the socket is readable. On Windows, RawConn.Read waits between
// calls with a zero-byte overlapped read, which completes when data, EOF
// or an error is pending, so the second call can report ready.
func readableWaiter() func(fd uintptr) bool {
	first := true
	return func(uintptr) bool {
		if first {
			first = false
			return false
		}
		first = true // re-arm for the next wait
		return true
	}
}
