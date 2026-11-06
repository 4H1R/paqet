package socket

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

var errNoPayload = errors.New("socket: packet carries no payload")

// skippable reports whether a read error only means "nothing usable yet".
func skippable(err error) bool { return err == errTimeout || err == errNoPayload }

// recvHandle decodes frames from a capture source. Payloads are not copied:
// they alias the capture buffer, which close must not release while a
// payload is in use.
type recvHandle struct {
	src  rxSource
	port uint16

	mu     sync.Mutex // held while a payload is in use
	addrs  addrCache
	frame  decodedFrame
	reaped bool

	closed atomic.Bool
}

func newRecvHandle(src rxSource, port int) *recvHandle {
	h := &recvHandle{src: src, port: uint16(port), addrs: make(addrCache)}
	registerRx(h)
	return h
}

// read waits for the next payload sent to the handle's port and passes it
// to use. The payload is only valid during the call. Errors for which
// skippable is true mean the caller should simply read again.
func (h *recvHandle) read(use func(payload []byte, from *Addr)) error {
	h.mu.Lock()
	err := h.readLocked(use)
	h.mu.Unlock()
	if h.closed.Load() {
		h.reap()
	}
	return err
}

func (h *recvHandle) readLocked(use func([]byte, *Addr)) error {
	if h.reaped || h.closed.Load() {
		return net.ErrClosed
	}
	f, err := h.src.next()
	if err != nil {
		return err
	}
	d := &h.frame
	// The port is checked again because no filter covers the moment
	// between opening a socket and attaching it.
	if !decodeFrame(f, d) || d.dstPort != h.port || len(d.payload) == 0 {
		return errNoPayload
	}
	use(d.payload, h.addrs.get(d.srcIP, d.srcPort))
	return nil
}

// reap releases the source once closed and no reader holds mu. close stores
// closed before trying the lock and read checks it after unlocking, so
// whichever runs last reaps.
func (h *recvHandle) reap() {
	if !h.mu.TryLock() {
		return
	}
	if !h.reaped {
		h.reaped = true
		unregisterRx(h)
		h.src.close()
	}
	h.mu.Unlock()
}

func (h *recvHandle) close() {
	h.closed.Store(true)
	h.src.wake()
	h.reap()
}

// Kernel drop counters of all receive handles, for the stats line.
var rxStats struct {
	sync.Mutex
	live        map[*recvHandle]struct{}
	closedDrops uint64
}

func registerRx(h *recvHandle) {
	rxStats.Lock()
	defer rxStats.Unlock()
	if rxStats.live == nil {
		rxStats.live = make(map[*recvHandle]struct{})
	}
	rxStats.live[h] = struct{}{}
}

func unregisterRx(h *recvHandle) {
	rxStats.Lock()
	defer rxStats.Unlock()
	if _, ok := rxStats.live[h]; ok {
		delete(rxStats.live, h)
		rxStats.closedDrops += h.src.drops()
	}
}

// Drops returns how many received packets the kernel dropped because a
// capture buffer was full.
func Drops() uint64 {
	rxStats.Lock()
	defer rxStats.Unlock()
	n := rxStats.closedDrops
	for h := range rxStats.live {
		n += h.src.drops()
	}
	return n
}
