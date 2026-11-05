package socket

import (
	"net"
	"testing"
)

func TestAddrCache(t *testing.T) {
	h := &RecvHandle{addrs: make(map[uint64]*net.UDPAddr)}

	buf := net.IP{10, 0, 0, 1}
	a := h.addr(buf, 1000)
	buf[3] = 2 // the capture buffer is reused; the cached address must not change
	if got := a.IP.String(); got != "10.0.0.1" {
		t.Fatalf("cached IP aliased the capture buffer: %s", got)
	}
	if b := h.addr(net.IP{10, 0, 0, 1}, 1000); b != a {
		t.Fatal("same source should reuse the cached address")
	}
	if c := h.addr(net.IP{10, 0, 0, 1}, 1001); c == a || c.Port != 1001 {
		t.Fatal("different port must not hit the cache")
	}

	// IPv6 keys are XOR-folded and can collide; equality must be verified.
	x := net.ParseIP("2001:db8::1")
	y := net.ParseIP("2001:db8::1:0:0:0:0") // differs only in a folded half
	ax, ay := h.addr(x, 53), h.addr(y, 53)
	if !ax.IP.Equal(x) || !ay.IP.Equal(y) {
		t.Fatalf("collision returned the wrong address: %v %v", ax, ay)
	}
}

func TestAddrCacheBounded(t *testing.T) {
	h := &RecvHandle{addrs: make(map[uint64]*net.UDPAddr)}
	for i := range maxCachedAddrs + 10 {
		h.addr(net.IP{10, byte(i >> 16), byte(i >> 8), byte(i)}, 1)
	}
	if len(h.addrs) > maxCachedAddrs {
		t.Fatalf("cache grew past bound: %d", len(h.addrs))
	}
}
