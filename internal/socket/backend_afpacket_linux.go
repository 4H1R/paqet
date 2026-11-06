//go:build linux

package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"paqet/internal/conf"
	"paqet/internal/flog"
)

// AF_PACKET backend: both directions go through TPACKET_V2 rings shared
// with the kernel, so under load neither receiving nor sending costs a
// system call per packet. TPACKET_V3 would batch receives better but holds
// frames until a block fills or times out, adding latency.

const afpacketSupported = true

const (
	ringFrameSize = captureSnapLen
	ringBlockSize = 64 * 1024 // a multiple of both the page and frame size
	ringPollMs    = 500       // bounds how long a missed wake can delay close

	packetIgnoreOutgoing = 23 // PACKET_IGNORE_OUTGOING, Linux 4.20+
)

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ringSize returns the number of blocks and frames for a ring of at least
// minFrames frames.
func ringSize(minFrames int) (blocks, frames int) {
	perBlock := ringBlockSize / ringFrameSize
	blocks = max((minFrames+perBlock-1)/perBlock, 1)
	return blocks, blocks * perBlock
}

// setupRing configures fd as a TPACKET_V2 socket with a ring of the given
// kind (PACKET_RX_RING or PACKET_TX_RING) and maps it.
func setupRing(fd, kind, minFrames int) (ring []byte, frames int, err error) {
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2); err != nil {
		return nil, 0, fmt.Errorf("PACKET_VERSION: %w", err)
	}
	blocks, frames := ringSize(minFrames)
	req := unix.TpacketReq{
		Block_size: ringBlockSize,
		Block_nr:   uint32(blocks),
		Frame_size: ringFrameSize,
		Frame_nr:   uint32(frames),
	}
	if err := unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, kind, &req); err != nil {
		return nil, 0, fmt.Errorf("ring setup: %w", err)
	}
	ring, err = unix.Mmap(fd, 0, blocks*ringBlockSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, 0, fmt.Errorf("mmap: %w", err)
	}
	return ring, frames, nil
}

func frameHdr(ring []byte, i int) *unix.Tpacket2Hdr {
	return (*unix.Tpacket2Hdr)(unsafe.Pointer(&ring[i*ringFrameSize]))
}

type ringRx struct {
	fd      int
	efd     int // eventfd for wake
	ring    []byte
	nframes int
	idx     int
	held    bool // frame idx is owned by user space until the next call

	mu      sync.Mutex // guards fds and stats against close
	dropped uint64
	closed  bool
}

func newAFPacketRx(cfg *conf.Network) (rxSource, error) {
	r, err := openRingRx(cfg.Interface.Index, uint16(cfg.Port), cfg.PCAP.Sockbuf)
	if err != nil {
		return nil, fmt.Errorf("failed to open AF_PACKET socket on %s: %w", cfg.Interface.Name, err)
	}
	return r, nil
}

func openRingRx(ifindex int, port uint16, bufBytes int) (r *ringRx, err error) {
	// Protocol 0 captures nothing until bind, so the filter and ring are in
	// place before the first frame arrives.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	r = &ringRx{fd: fd, efd: -1}
	defer func() {
		if err != nil {
			r.close()
		}
	}()

	prog, err := captureFilter(port, true)
	if err != nil {
		return nil, fmt.Errorf("BPF filter: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return nil, fmt.Errorf("SO_ATTACH_FILTER: %w", err)
	}
	// Optional: the filter rejects outgoing frames on kernels without it.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetIgnoreOutgoing, 1)

	if r.ring, r.nframes, err = setupRing(fd, unix.PACKET_RX_RING, bufBytes/ringFrameSize); err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	if r.efd, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK); err != nil {
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	// The kernel counts drops from socket creation; start from zero.
	_, _ = unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	return r, nil
}

func (r *ringRx) next() ([]byte, error) {
	if r.held {
		// The atomic store orders our reads of the frame before its reuse.
		atomic.StoreUint32(&frameHdr(r.ring, r.idx).Status, unix.TP_STATUS_KERNEL)
		r.idx = (r.idx + 1) % r.nframes
		r.held = false
	}

	hdr := frameHdr(r.ring, r.idx)
	for atomic.LoadUint32(&hdr.Status)&unix.TP_STATUS_USER == 0 {
		if err := r.wait(); err != nil {
			return nil, err
		}
	}

	r.held = true
	start, end := int(hdr.Mac), int(hdr.Mac)+int(hdr.Snaplen)
	if end > ringFrameSize {
		return nil, nil // malformed descriptor; decoding rejects the empty frame
	}
	base := r.idx * ringFrameSize
	return r.ring[base+start : base+end : base+end], nil
}

// wait blocks until the ring may have a frame. It returns errTimeout when
// woken or after ringPollMs.
func (r *ringRx) wait() error {
	fds := [2]unix.PollFd{
		{Fd: int32(r.fd), Events: unix.POLLIN},
		{Fd: int32(r.efd), Events: unix.POLLIN},
	}
	n, err := unix.Poll(fds[:], ringPollMs)
	switch {
	case errors.Is(err, unix.EINTR):
		return nil
	case err != nil:
		return err
	case n == 0:
		return errTimeout
	case fds[1].Revents != 0:
		var b [8]byte
		_, _ = unix.Read(r.efd, b[:])
		return errTimeout
	case fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0:
		// Reading SO_ERROR clears it. A downed interface comes back on its
		// own, so keep waiting instead of failing the session.
		soerr, err := unix.GetsockoptInt(r.fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if soerr != 0 && unix.Errno(soerr) != unix.ENETDOWN {
			return unix.Errno(soerr)
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			return errTimeout
		}
	}
	return nil
}

func (r *ringRx) drops() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectDropsLocked()
	return r.dropped
}

// collectDropsLocked adds the kernel counter, which resets on read.
func (r *ringRx) collectDropsLocked() {
	if r.closed {
		return
	}
	if st, err := unix.GetsockoptTpacketStats(r.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		r.dropped += uint64(st.Drops)
	}
}

func (r *ringRx) wake() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.efd < 0 {
		return
	}
	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(r.efd, one[:])
}

func (r *ringRx) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.collectDropsLocked()
	r.closed = true
	if r.ring != nil {
		_ = unix.Munmap(r.ring)
	}
	_ = unix.Close(r.fd)
	if r.efd >= 0 {
		_ = unix.Close(r.efd)
	}
}

func newAFPacketTx(cfg *conf.Network) (txSink, error) {
	t, err := newRingTx(cfg.Interface.Index, cfg.PCAP.Sockbuf/4/ringFrameSize)
	if err == nil {
		return t, nil
	}
	flog.Warnf("AF_PACKET transmit ring unavailable, sending one packet per system call: %v", err)
	return newRawTx(cfg.Interface.Index)
}

// ringTx sends through a PACKET_TX_RING. write copies the frame into the
// ring and returns; a flusher goroutine then has the kernel transmit
// everything queued with a single send(), and the kernel keeps picking up
// frames queued while it works. Profiling showed the per-packet sendto as
// the largest CPU cost of the transport; this makes it one call per burst.
//
// Transmit errors surface asynchronously, on the next write.
type ringTx struct {
	fd      int
	ring    []byte
	nframes int

	mu     sync.Mutex
	idx    int  // next slot to fill, guarded by mu
	closed bool // guarded by mu

	kick chan struct{}
	done chan struct{}
	wg   sync.WaitGroup
	err  atomic.Pointer[error]
}

const (
	// txDataOff is where frame data starts in a TX slot: TPACKET2_HDRLEN
	// minus the sockaddr_ll the kernel expects in front of it.
	txDataOff  = 32
	txMaxFrame = ringFrameSize - txDataOff

	// Ring bounds. The default sockbufs give 512 frames on the client and
	// 1024 on the server, a full KCP send window.
	txMinFrames = 128
	txMaxFrames = 4096
)

var errFrameTooLarge = errors.New("socket: frame too large")

func newRingTx(ifindex, minFrames int) (t *ringTx, err error) {
	// Protocol 0: the socket only sends. The kernel infers each frame's
	// protocol from its Ethernet header.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	t = &ringTx{fd: fd, kick: make(chan struct{}, 1), done: make(chan struct{})}
	defer func() {
		if err != nil {
			if t.ring != nil {
				_ = unix.Munmap(t.ring)
			}
			_ = unix.Close(fd)
		}
	}()

	// Skip malformed frames instead of stalling the ring on them.
	if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_LOSS, 1); err != nil {
		return nil, fmt.Errorf("PACKET_LOSS: %w", err)
	}
	minFrames = min(max(minFrames, txMinFrames), txMaxFrames)
	if t.ring, t.nframes, err = setupRing(fd, unix.PACKET_TX_RING, minFrames); err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifindex}); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	// Bounds the flusher's wait for frames to leave, so close cannot hang
	// on a stuck device.
	tv := unix.Timeval{Sec: 1}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("SO_SNDTIMEO: %w", err)
	}
	t.wg.Add(1)
	go t.flushLoop()
	return t, nil
}

func (t *ringTx) write(frame []byte) error {
	if len(frame) > txMaxFrame {
		return errFrameTooLarge
	}
	if p := t.err.Swap(nil); p != nil {
		return *p
	}

	t.mu.Lock()
	for {
		if t.closed {
			t.mu.Unlock()
			return net.ErrClosed
		}
		if atomic.LoadUint32(&frameHdr(t.ring, t.idx).Status) == unix.TP_STATUS_AVAILABLE {
			break
		}
		// Ring full: wait for the kernel to free a slot, like a full socket
		// buffer would block sendto.
		t.mu.Unlock()
		t.signal()
		time.Sleep(50 * time.Microsecond)
		t.mu.Lock()
	}
	hdr := frameHdr(t.ring, t.idx)
	base := t.idx*ringFrameSize + txDataOff
	t.idx = (t.idx + 1) % t.nframes
	copy(t.ring[base:base+len(frame)], frame)
	hdr.Len = uint32(len(frame))
	// The atomic store publishes the copy before the kernel sees the request.
	atomic.StoreUint32(&hdr.Status, unix.TP_STATUS_SEND_REQUEST)
	t.mu.Unlock()

	t.signal()
	return nil
}

func (t *ringTx) signal() {
	select {
	case t.kick <- struct{}{}:
	default: // a pending flush will pick the frame up
	}
}

func (t *ringTx) flushLoop() {
	defer t.wg.Done()
	for {
		select {
		case <-t.kick:
		case <-t.done:
			return
		}
		t.flush()
	}
}

// flush transmits every queued frame. A blocking send with no buffer also
// takes frames queued while it runs and returns once they have left.
func (t *ringTx) flush() {
	for {
		_, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(t.fd), 0, 0, 0, 0, 0)
		switch errno {
		case 0:
			return
		case unix.EINTR:
		case unix.ENOBUFS, unix.EAGAIN, unix.ETIMEDOUT:
			// Congestion: the frames stay queued. Reporting it would make
			// kcp-go drop a healthy session.
			time.Sleep(100 * time.Microsecond)
		default:
			// The interface went away or down; let the sessions notice.
			err := error(errno)
			t.err.Store(&err)
			return
		}
	}
}

func (t *ringTx) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	close(t.done)
	t.wg.Wait()
	_ = unix.Munmap(t.ring)
	_ = unix.Close(t.fd)
}

// rawTx sends one frame per system call, for kernels without a TX ring.
type rawTx struct {
	fd     int
	v4, v6 unix.SockaddrLinklayer
}

func newRawTx(ifindex int) (txSink, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open AF_PACKET send socket: %w", err)
	}
	return &rawTx{
		fd: fd,
		v4: unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: ifindex},
		v6: unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: ifindex},
	}, nil
}

func (t *rawTx) write(frame []byte) error {
	sa := &t.v4
	if len(frame) >= ethHdrLen && binary.BigEndian.Uint16(frame[12:]) == etherTypeIPv6 {
		sa = &t.v6
	}
	for {
		if err := unix.Sendto(t.fd, frame, 0, sa); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func (t *rawTx) close() { _ = unix.Close(t.fd) }
