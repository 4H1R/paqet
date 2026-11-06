//go:build !unix

package buffer

// readableWaiter returns a RawConn.Read callback that waits for the socket
// to become readable. On Windows RawConn.Read waits between calls with a
// zero-byte read that completes on data, EOF or an error, so the second
// call can report ready.
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
