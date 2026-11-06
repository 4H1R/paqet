//go:build linux

package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"paqet/internal/conf"
	"paqet/internal/flog"
)

// AF_PACKET backend. Receiving uses a TPACKET_V2 memory-mapped ring, so a
// busy reader takes frames straight out of shared memory with no system
// call and no cgo call per packet. TPACKET_V3 would batch better, but it
// holds frames back until a block fills or times out, which adds latency.
// Sending uses a plain packet socket that captures nothing, so it needs no
// ring and no filter.

const afpacketSupported = true

const (
	ringFrameSize = captureSnapLen // tpacket2 header + up to ~1980 bytes of frame
	ringBlockSize = 64 * 1024      // multiple of the page size and the frame size
	ringPollMs    = 500            // re-check for shutdown even if wake fails

	packetIgnoreOutgoing    = 23     // PACKET_IGNORE_OUTGOING, Linux 4.20+
	packetFanoutFlagUniqID  = 0x2000 // PACKET_FANOUT_FLAG_UNIQUEID, Linux 4.4+
	packetFanoutHashAndFlag = unix.PACKET_FANOUT_HASH | packetFanoutFlagUniqID
)

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

type ringRx struct {
	fd      int
	efd     int
	ring    []byte
	nframes int
	idx     int
	held    bool // frame idx belongs to user space until the next call

	statsMu sync.Mutex // guards fd for stats, dropped and closed
	dropped uint64
	closed  bool
}

func newAFPacketRx(cfg *conf.Network, readers int) ([]rxSource, error) {
	readers = max(readers, 1)
	prog, err := captureFilter(uint16(cfg.Port), true)
	if err != nil {
		return nil, fmt.Errorf("failed to build BPF filter: %w", err)
	}
	ringBytes := max(cfg.PCAP.Sockbuf/readers, ringBlockSize)

	first, err := openRing(cfg.Interface.Index, ringBytes, prog)
	if err != nil {
		return nil, fmt.Errorf("failed to open AF_PACKET socket on %s: %w", cfg.Interface.Name, err)
	}
	if readers == 1 {
		return []rxSource{first}, nil
	}

	// Spread the traffic over several rings by flow hash. Each peer is one
	// flow, so its packets always reach the same reader. The kernel picks
	// a group id that no other socket in this network namespace uses.
	group, err := first.joinFanout(-1)
	if err != nil {
		flog.Warnf("AF_PACKET fanout unavailable, using one reader: %v", err)
		return []rxSource{first}, nil
	}
	srcs := []rxSource{first}
	for len(srcs) < readers {
		r, err := openRing(cfg.Interface.Index, ringBytes, prog)
		if err == nil {
			_, err = r.joinFanout(group)
			if err != nil {
				r.close()
			}
		}
		if err != nil {
			for _, s := range srcs {
				s.close()
			}
			return nil, fmt.Errorf("failed to add AF_PACKET fanout reader on %s: %w", cfg.Interface.Name, err)
		}
		srcs = append(srcs, r)
	}
	return srcs, nil
}

func openRing(ifindex, ringBytes int, prog []bpf.RawInstruction) (r *ringRx, err error) {
	// Protocol 0 captures nothing until bind, so the filter and ring are in
	// place before the first frame can arrive.
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

	if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2); err != nil {
		return nil, fmt.Errorf("PACKET_VERSION: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return nil, fmt.Errorf("SO_ATTACH_FILTER: %w", err)
	}
	// Skip our own outgoing frames before they reach the filter. Older
	// kernels lack this option; the filter rejects them instead.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetIgnoreOutgoing, 1)

	blocks := (ringBytes + ringBlockSize - 1) / ringBlockSize
	req := unix.TpacketReq{
		Block_size: ringBlockSize,
		Block_nr:   uint32(blocks),
		Frame_size: ringFrameSize,
		Frame_nr:   uint32(blocks * (ringBlockSize / ringFrameSize)),
	}
	if err = unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		return nil, fmt.Errorf("PACKET_RX_RING: %w", err)
	}
	r.ring, err = unix.Mmap(fd, 0, blocks*ringBlockSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap ring: %w", err)
	}
	r.nframes = int(req.Frame_nr)

	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	if r.efd, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK); err != nil {
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	// Reset the kernel counters; they count from socket creation.
	_, _ = unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	return r, nil
}

// joinFanout adds the socket to fanout group id, or creates a new group
// with a kernel-assigned id when id < 0. It returns the group id.
func (r *ringRx) joinFanout(id int) (int, error) {
	if id < 0 {
		if err := unix.SetsockoptInt(r.fd, unix.SOL_PACKET, unix.PACKET_FANOUT, packetFanoutHashAndFlag<<16); err != nil {
			return 0, fmt.Errorf("PACKET_FANOUT: %w", err)
		}
		v, err := unix.GetsockoptInt(r.fd, unix.SOL_PACKET, unix.PACKET_FANOUT)
		if err != nil {
			return 0, fmt.Errorf("PACKET_FANOUT id: %w", err)
		}
		return v & 0xffff, nil
	}
	if err := unix.SetsockoptInt(r.fd, unix.SOL_PACKET, unix.PACKET_FANOUT, unix.PACKET_FANOUT_HASH<<16|id); err != nil {
		return 0, fmt.Errorf("PACKET_FANOUT: %w", err)
	}
	return id, nil
}

func (r *ringRx) frame(i int) *unix.Tpacket2Hdr {
	return (*unix.Tpacket2Hdr)(unsafe.Pointer(&r.ring[i*ringFrameSize]))
}

func (r *ringRx) next() ([]byte, error) {
	if r.held {
		// Hand the previous frame back to the kernel. The store is atomic,
		// so all reads of its data happen before the kernel reuses it.
		atomic.StoreUint32(&r.frame(r.idx).Status, unix.TP_STATUS_KERNEL)
		r.idx++
		if r.idx == r.nframes {
			r.idx = 0
		}
		r.held = false
	}

	hdr := r.frame(r.idx)
	for atomic.LoadUint32(&hdr.Status)&unix.TP_STATUS_USER == 0 {
		fds := [2]unix.PollFd{
			{Fd: int32(r.fd), Events: unix.POLLIN},
			{Fd: int32(r.efd), Events: unix.POLLIN},
		}
		n, err := unix.Poll(fds[:], ringPollMs)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return nil, err
		case fds[1].Revents != 0:
			var b [8]byte
			_, _ = unix.Read(r.efd, b[:])
			return nil, errTimeout
		case n == 0:
			return nil, errTimeout
		case fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0:
			// Reading SO_ERROR clears it. A downed interface comes back on
			// its own, so keep waiting rather than failing the session.
			soerr, gerr := unix.GetsockoptInt(r.fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if gerr != nil {
				return nil, gerr
			}
			if soerr != 0 && unix.Errno(soerr) != unix.ENETDOWN {
				return nil, unix.Errno(soerr)
			}
			if fds[0].Revents&unix.POLLIN == 0 {
				return nil, errTimeout
			}
		}
	}

	r.held = true
	start := int(hdr.Mac)
	end := start + int(hdr.Snaplen)
	if start < 0 || end > ringFrameSize || start > end {
		return nil, nil // malformed descriptor: report an empty frame
	}
	base := r.idx * ringFrameSize
	return r.ring[base+start : base+end : base+end], nil
}

func (r *ringRx) drops() uint64 {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.pollStatsLocked()
	return r.dropped
}

// pollStatsLocked folds the kernel counters, which reset on every read,
// into the running total.
func (r *ringRx) pollStatsLocked() {
	if r.closed || r.fd < 0 {
		return
	}
	if st, err := unix.GetsockoptTpacketStats(r.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		r.dropped += uint64(st.Drops)
	}
}

func (r *ringRx) wake() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if r.closed || r.efd < 0 {
		return
	}
	one := [8]byte{}
	binary.NativeEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(r.efd, one[:])
}

func (r *ringRx) close() {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if r.closed {
		return
	}
	r.pollStatsLocked()
	r.closed = true
	if r.ring != nil {
		_ = unix.Munmap(r.ring)
		r.ring = nil
	}
	if r.fd >= 0 {
		_ = unix.Close(r.fd)
		r.fd = -1
	}
	if r.efd >= 0 {
		_ = unix.Close(r.efd)
		r.efd = -1
	}
}

type rawTx struct {
	fd     int
	v4, v6 unix.SockaddrLinklayer
}

func newAFPacketTx(cfg *conf.Network) (txSink, error) {
	// Protocol 0: the socket only sends and never queues received frames.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open AF_PACKET send socket: %w", err)
	}
	t := &rawTx{
		fd: fd,
		v4: unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: cfg.Interface.Index},
		v6: unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: cfg.Interface.Index},
	}
	return t, nil
}

func (t *rawTx) write(frame []byte) error {
	sa := &t.v4
	if len(frame) > 13 && binary.BigEndian.Uint16(frame[12:]) == etherTypeIPv6 {
		sa = &t.v6
	}
	for {
		err := unix.Sendto(t.fd, frame, 0, sa)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func (t *rawTx) close() { _ = unix.Close(t.fd) }
