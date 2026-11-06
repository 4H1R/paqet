//go:build unix

package buffer

import (
	"errors"

	"golang.org/x/sys/unix"
)

// readableWaiter returns a syscall.RawConn.Read callback that completes
// once the socket has data, EOF or an error pending. It peeks with
// MSG_DONTWAIT so it never consumes data. The netpoller is edge
// triggered, so readiness must be checked rather than assumed: data left
// over from an earlier read raises no new edge.
func readableWaiter() func(fd uintptr) bool {
	var b [1]byte
	return func(fd uintptr) bool {
		_, _, err := unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR)
	}
}
