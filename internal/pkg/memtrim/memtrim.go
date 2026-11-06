// Package memtrim returns freed memory to the OS once traffic goes quiet.
//
// After a burst the Go runtime keeps freed heap for minutes, and pooled
// buffers stay live until two collections pass. A proxy that is mostly
// idle would hold its peak footprint long after the traffic is gone.
package memtrim

import (
	"context"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"time"
)

const (
	checkEvery = 15 * time.Second
	// quietBytes is the most traffic per check interval that still counts
	// as idle; keepalives and stray packets stay well below it.
	quietBytes = 4 << 20
	// minHeld skips trimming small processes, where it would gain little.
	minHeld = 16 << 20
)

// Run trims memory once each time traffic, a monotonic byte counter, goes
// quiet. It returns when ctx is done.
func Run(ctx context.Context, traffic func() uint64) {
	t := &trimmer{traffic: traffic, held: heldBytes, trim: trim}
	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.check()
		}
	}
}

type trimmer struct {
	traffic func() uint64
	held    func() uint64
	trim    func()

	last    uint64
	started bool
	trimmed bool // since traffic last went quiet
}

func (t *trimmer) check() {
	cur := t.traffic()
	busy := !t.started || cur-t.last >= quietBytes
	t.last, t.started = cur, true
	if busy {
		t.trimmed = false
		return
	}
	if t.trimmed || t.held() < minHeld {
		return
	}
	t.trim()
	t.trimmed = true
}

func trim() {
	runtime.GC() // moves pooled buffers aside; the next collection frees them
	debug.FreeOSMemory()
}

// heldBytes is the heap memory the process holds from the OS.
func heldBytes() uint64 {
	s := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
	}
	metrics.Read(s)
	var n uint64
	for _, v := range s {
		if v.Value.Kind() == metrics.KindUint64 {
			n += v.Value.Uint64()
		}
	}
	return n
}
