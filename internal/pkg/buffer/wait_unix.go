//go:build unix

package buffer

import (
	"errors"

	"golang.org/x/sys/unix"
)

// readableWaiter returns a RawConn.Read callback that reports whether data,
// EOF or an error is pending, without consuming anything. Readiness has to
// be checked: the netpoller is edge triggered, so data left over from an
// earlier read raises no new edge.
func readableWaiter() func(fd uintptr) bool {
	var b [1]byte
	return func(fd uintptr) bool {
		_, _, err := unix.Recvfrom(int(fd), b[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR)
	}
}
