package memtrim

import "testing"

func TestTrimsOncePerQuietPeriod(t *testing.T) {
	var traffic, trims uint64
	held := uint64(minHeld)
	tr := &trimmer{
		traffic: func() uint64 { return traffic },
		held:    func() uint64 { return held },
		trim:    func() { trims++ },
	}
	step := func(bytes uint64) { traffic += bytes; tr.check() }

	step(0) // first sample only sets the baseline
	if trims != 0 {
		t.Fatal("trimmed without a baseline")
	}
	step(100 << 20) // busy
	step(1 << 10)   // quiet: trim
	step(0)         // still quiet: no second trim
	if trims != 1 {
		t.Fatalf("trims = %d, want 1", trims)
	}
	step(quietBytes) // busy again
	step(0)          // quiet again: trim again
	if trims != 2 {
		t.Fatalf("trims = %d, want 2", trims)
	}

	step(quietBytes)
	held = minHeld - 1 // too small to bother
	step(0)
	if trims != 2 {
		t.Fatal("trimmed a small process")
	}
}

func TestHeldBytes(t *testing.T) {
	if heldBytes() == 0 {
		t.Fatal("runtime metrics unavailable")
	}
}
