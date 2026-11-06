//go:build windows

package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/windows"

	"paqet/internal/conf"
	"paqet/internal/flog"
)

// queueTx sends through Npcap send queues. write appends the frame to a
// queue buffer and returns; a flusher goroutine hands the whole buffer to
// pcap_sendqueue_transmit, one kernel call per burst instead of one
// pcap_sendpacket per packet. Two buffers alternate, so writers keep
// filling one while the other is transmitted.
//
// Transmit errors surface asynchronously, on the next write.
type queueTx struct {
	p        uintptr // pcap_t*
	fn       *npcapFuncs
	transmit func(*sendQueue) error
	mu       sync.Mutex
	cond     sync.Cond  // signalled when a buffer is swapped in
	active   *sendQueue // filled by writers, guarded by mu
	spare    *sendQueue // owned by the flusher
	closed   bool       // guarded by mu
	kick     chan struct{}
	done     chan struct{}
	wg       sync.WaitGroup
	err      atomic.Pointer[error]
}

// sendQueue mirrors struct pcap_send_queue, followed by its Go-owned buffer.
type sendQueue struct {
	hdr struct {
		maxlen uint32
		len    uint32
		buffer uintptr
	}
	buf []byte
}

const (
	// pcapPkthdrLen is sizeof(struct pcap_pkthdr) on Windows, where the
	// timeval members are 32-bit longs.
	pcapPkthdrLen = 16
	sendQueueSize = 512 * 1024
)

func newSendQueue() *sendQueue {
	q := &sendQueue{buf: make([]byte, sendQueueSize)}
	q.hdr.maxlen = sendQueueSize
	q.hdr.buffer = uintptr(unsafe.Pointer(&q.buf[0]))
	return q
}

type npcapFuncs struct {
	openLive, setbuff, compile, setfilter, freecode, transmit, geterr, close uintptr
}

var (
	npcapOnce sync.Once
	npcap     *npcapFuncs
	npcapErr  error
)

func loadNpcap() (*npcapFuncs, error) {
	npcapOnce.Do(func() {
		if err := pcap.LoadWinPCAP(); err != nil {
			npcapErr = err
			return
		}
		// gopacket has loaded Npcap's wpcap.dll; use the same module.
		var h windows.Handle
		const unchangedRefcount = 0x2 // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
		if err := windows.GetModuleHandleEx(unchangedRefcount, windows.StringToUTF16Ptr("wpcap.dll"), &h); err != nil {
			npcapErr = fmt.Errorf("wpcap.dll: %w", err)
			return
		}
		f := &npcapFuncs{}
		var err error
		for name, p := range map[string]*uintptr{
			"pcap_open_live":          &f.openLive,
			"pcap_setbuff":            &f.setbuff,
			"pcap_compile":            &f.compile,
			"pcap_setfilter":          &f.setfilter,
			"pcap_freecode":           &f.freecode,
			"pcap_sendqueue_transmit": &f.transmit,
			"pcap_geterr":             &f.geterr,
			"pcap_close":              &f.close,
		} {
			if *p, err = windows.GetProcAddress(h, name); err != nil {
				npcapErr = fmt.Errorf("%s: %w", name, err)
				return
			}
		}
		npcap = f
	})
	return npcap, npcapErr
}

func newPcapTx(cfg *conf.Network) (txSink, error) {
	t, err := newQueueTx(cfg.GUID)
	if err == nil {
		return t, nil
	}
	flog.Warnf("Npcap send queues unavailable, sending one packet per call: %v", err)
	return newPcapPacketTx(cfg)
}

func newQueueTx(device string) (*queueTx, error) {
	fn, err := loadNpcap()
	if err != nil {
		return nil, err
	}
	dev, err := windows.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	var errbuf [256]byte
	p, _, _ := syscall.SyscallN(fn.openLive, uintptr(unsafe.Pointer(dev)), 128, 0, 1000, uintptr(unsafe.Pointer(&errbuf[0])))
	if p == 0 {
		return nil, fmt.Errorf("pcap_open_live %s: %s", device, windows.ByteSliceToString(errbuf[:]))
	}
	t := newQueueTxWith(func(q *sendQueue) error {
		sent, _, _ := syscall.SyscallN(fn.transmit, p, uintptr(unsafe.Pointer(&q.hdr)), 0)
		if uint32(sent) < q.hdr.len {
			return errors.New("pcap_sendqueue_transmit: " + pcapLastError(fn, p))
		}
		return nil
	})
	t.p, t.fn = p, fn
	// The handle only sends: capture nothing, into a small kernel buffer.
	if err := t.rejectAll(); err != nil {
		t.close()
		return nil, err
	}
	syscall.SyscallN(fn.setbuff, p, 64*1024)
	return t, nil
}

func newQueueTxWith(transmit func(*sendQueue) error) *queueTx {
	t := &queueTx{transmit: transmit, active: newSendQueue(), spare: newSendQueue(),
		kick: make(chan struct{}, 1), done: make(chan struct{})}
	t.cond.L = &t.mu
	t.wg.Add(1)
	go t.flushLoop()
	return t
}

func (t *queueTx) rejectAll() error {
	var prog struct {
		len   uint32
		insns uintptr
	}
	expr, _ := windows.BytePtrFromString("less 0")
	if r, _, _ := syscall.SyscallN(t.fn.compile, t.p, uintptr(unsafe.Pointer(&prog)), uintptr(unsafe.Pointer(expr)), 1, 0xffffffff); int32(r) < 0 {
		return fmt.Errorf("pcap_compile: %s", t.lastError())
	}
	defer syscall.SyscallN(t.fn.freecode, uintptr(unsafe.Pointer(&prog)))
	if r, _, _ := syscall.SyscallN(t.fn.setfilter, t.p, uintptr(unsafe.Pointer(&prog))); int32(r) < 0 {
		return fmt.Errorf("pcap_setfilter: %s", t.lastError())
	}
	return nil
}

func (t *queueTx) lastError() string { return pcapLastError(t.fn, t.p) }

func pcapLastError(fn *npcapFuncs, p uintptr) string {
	r, _, _ := syscall.SyscallN(fn.geterr, p)
	return windows.BytePtrToString(*(**byte)(unsafe.Pointer(&r))) // C string owned by Npcap
}

func (t *queueTx) write(frame []byte) error {
	need := pcapPkthdrLen + len(frame)
	if need > sendQueueSize {
		return errFrameTooLarge
	}
	if p := t.err.Swap(nil); p != nil {
		return *p
	}

	t.mu.Lock()
	for !t.closed && int(t.active.hdr.len)+need > len(t.active.buf) {
		// Both buffers are busy: wait for the flusher, like a full socket
		// buffer would block a send.
		t.signal()
		t.cond.Wait()
	}
	if t.closed {
		t.mu.Unlock()
		return net.ErrClosed
	}
	q := t.active
	b := q.buf[q.hdr.len:]
	clear(b[:8]) // timestamp; ignored when the queue is sent unsynchronized
	binary.LittleEndian.PutUint32(b[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(frame)))
	copy(b[pcapPkthdrLen:], frame)
	q.hdr.len += uint32(need)
	t.mu.Unlock()

	t.signal()
	return nil
}

func (t *queueTx) signal() {
	select {
	case t.kick <- struct{}{}:
	default: // a pending flush will pick the frame up
	}
}

func (t *queueTx) flushLoop() {
	defer t.wg.Done()
	for {
		select {
		case <-t.kick:
		case <-t.done:
			return
		}
		for t.flush() {
		}
	}
}

// flush transmits the active queue, if it has frames, and reports whether
// it did.
func (t *queueTx) flush() bool {
	t.mu.Lock()
	q := t.active
	if q.hdr.len == 0 {
		t.mu.Unlock()
		return false
	}
	t.active, t.spare = t.spare, q
	t.cond.Broadcast()
	t.mu.Unlock()

	if err := t.transmit(q); err != nil {
		t.err.Store(&err)
	}
	q.hdr.len = 0
	return true
}

func (t *queueTx) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.cond.Broadcast()
	t.mu.Unlock()
	close(t.done)
	t.wg.Wait()
	if t.p != 0 {
		syscall.SyscallN(t.fn.close, t.p)
	}
}
