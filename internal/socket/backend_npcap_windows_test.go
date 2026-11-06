//go:build windows

package socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// parseQueue decodes a send queue the way Npcap does.
func parseQueue(t *testing.T, q *sendQueue) [][]byte {
	t.Helper()
	var out [][]byte
	b := q.buf[:q.hdr.len]
	for len(b) > 0 {
		caplen := binary.LittleEndian.Uint32(b[8:])
		if binary.LittleEndian.Uint32(b[12:]) != caplen || int(caplen)+pcapPkthdrLen > len(b) {
			t.Fatalf("bad packet header %x", b[:pcapPkthdrLen])
		}
		out = append(out, bytes.Clone(b[pcapPkthdrLen:pcapPkthdrLen+caplen]))
		b = b[pcapPkthdrLen+caplen:]
	}
	if q.hdr.buffer != uintptr(unsafe.Pointer(&q.buf[0])) || q.hdr.maxlen != uint32(len(q.buf)) {
		t.Fatal("queue header does not describe its buffer")
	}
	return out
}

func TestQueueTxDeliversInOrder(t *testing.T) {
	var mu sync.Mutex
	var got [][]byte
	batches := 0
	tx := newQueueTxWith(func(q *sendQueue) error {
		frames := parseQueue(t, q)
		mu.Lock()
		got = append(got, frames...)
		batches++
		mu.Unlock()
		time.Sleep(time.Millisecond) // let writers fill the other buffer
		return nil
	})

	const writers, perWriter = 8, 2000
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				// Large frames fill buffers quickly and exercise back-pressure.
				f := bytes.Repeat([]byte{byte(w)}, 1400)
				copy(f, fmt.Sprintf("%d:%d:", w, i))
				if err := tx.write(f); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == writers*perWriter || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	tx.close()

	next := make([]int, writers)
	for _, f := range got {
		var w, i int
		fmt.Sscanf(string(f), "%d:%d:", &w, &i)
		if i != next[w] || len(f) != 1400 {
			t.Fatalf("writer %d: frame %d out of order or damaged (want %d)", w, i, next[w])
		}
		next[w]++
	}
	if len(got) != writers*perWriter {
		t.Fatalf("delivered %d of %d frames", len(got), writers*perWriter)
	}
	if batches >= len(got) {
		t.Errorf("no batching: %d transmits for %d frames", batches, len(got))
	}
	t.Logf("%d frames in %d transmits", len(got), batches)
}

func TestQueueTxReportsErrorAndCloses(t *testing.T) {
	fail := errors.New("boom")
	tx := newQueueTxWith(func(*sendQueue) error { return fail })
	if err := tx.write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if err := tx.write([]byte("b")); errors.Is(err, fail) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("transmit error never surfaced")
		}
		time.Sleep(time.Millisecond)
	}
	if err := tx.write(make([]byte, sendQueueSize)); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("oversized frame: %v", err)
	}
	tx.close()
	if err := tx.write([]byte("c")); err == nil {
		t.Fatal("write after close succeeded")
	}
}
