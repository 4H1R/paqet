package socket

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

var errNoPayload = errors.New("socket: packet carries no payload")

// RecvHandle reads frames from one capture source and decodes them.
//
// Reads are zero-copy: a returned payload aliases the capture buffer and is
// valid until the next read. mu is held from a read until the caller is
// done with the payload, and the source is only closed by whoever next
// holds mu after Close, so closing never frees memory a reader still uses.
type RecvHandle struct {
	src  rxSource
	port uint16

	mu    sync.Mutex
	addrs addrCache    // guarded by mu
	frame decodedFrame // guarded by mu

	closed atomic.Bool
	reaped bool // guarded by mu
}

func newRecvHandle(src rxSource, port int) *RecvHandle {
	h := &RecvHandle{src: src, port: uint16(port), addrs: make(addrCache)}
	registerRx(h)
	return h
}

// readLocked returns the next payload sent to the handle's port and its
// source. The caller must hold mu until it is done with the payload.
func (h *RecvHandle) readLocked() ([]byte, *Addr, error) {
	if h.closed.Load() || h.reaped {
		return nil, nil, net.ErrClosed
	}
	f, err := h.src.next()
	if err != nil {
		return nil, nil, err
	}
	d := &h.frame
	// The capture filter already matched the port; checking again keeps
	// stray frames out during setup and on backends without a filter.
	if !decodeFrame(f, d) || d.dstPort != h.port || len(d.payload) == 0 {
		return nil, nil, errNoPayload
	}
	return d.payload, h.addrs.get(d.srcIP, d.srcPort), nil
}

// unlock releases mu and finishes a Close that happened meanwhile.
func (h *RecvHandle) unlock() {
	h.mu.Unlock()
	if h.closed.Load() {
		h.reap()
	}
}

// reap closes the source if Close was called and no reader holds mu. If a
// reader does, it reaps on unlock. Close stores closed before trying the
// lock and readers load it after unlocking, so one of them always reaps.
func (h *RecvHandle) reap() {
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

// Close stops the handle. A blocked reader is woken; the capture source is
// released once it returns.
func (h *RecvHandle) Close() {
	h.closed.Store(true)
	h.src.wake()
	h.reap()
}

// Kernel drop accounting across all receive handles, for the stats line.
var rxStats struct {
	sync.Mutex
	live        map[*RecvHandle]struct{}
	closedDrops uint64
}

func registerRx(h *RecvHandle) {
	rxStats.Lock()
	if rxStats.live == nil {
		rxStats.live = make(map[*RecvHandle]struct{})
	}
	rxStats.live[h] = struct{}{}
	rxStats.Unlock()
}

func unregisterRx(h *RecvHandle) {
	rxStats.Lock()
	if _, ok := rxStats.live[h]; ok {
		delete(rxStats.live, h)
		rxStats.closedDrops += h.src.drops()
	}
	rxStats.Unlock()
}

// Drops returns how many received frames the kernel dropped, across all
// receive handles, because the capture buffer was full.
func Drops() uint64 {
	rxStats.Lock()
	defer rxStats.Unlock()
	n := rxStats.closedDrops
	for h := range rxStats.live {
		n += h.src.drops()
	}
	return n
}
