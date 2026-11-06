package socks

import (
	"bytes"
	"testing"
)

func TestDecodeDatagram(t *testing.T) {
	cases := []struct {
		name    string
		pkt     []byte
		key     []byte
		address string
		data    string
	}{
		{"ipv4", []byte{0, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 53, 'h', 'i'}, []byte{atypIPv4, 1, 2, 3, 4, 0, 53}, "1.2.3.4:53", "hi"},
		{"domain", append([]byte{0, 0, 0, atypDomain, 3, 'a', '.', 'b', 1, 187}, 'x'), []byte{atypDomain, 3, 'a', '.', 'b', 1, 187}, "a.b:443", "x"},
		{"ipv6", append(append([]byte{0, 0, 0, atypIPv6}, make([]byte, 15)...), 1, 0, 80), append(append([]byte{atypIPv6}, make([]byte, 15)...), 1, 0, 80), "[::1]:80", ""},
	}
	for _, c := range cases {
		d, key, err := decodeDatagram(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !bytes.Equal(key, c.key) || d.address() != c.address || string(d.data) != c.data {
			t.Fatalf("%s: key %v address %q data %q", c.name, key, d.address(), d.data)
		}
	}
	for _, bad := range [][]byte{{0, 0}, {0, 0, 1, atypIPv4, 1, 2, 3, 4, 0, 1}, {0, 0, 0, atypDomain, 9, 'a'}, {0, 0, 0, 9}} {
		if _, _, err := decodeDatagram(bad); err == nil {
			t.Fatalf("accepted malformed datagram %v", bad)
		}
	}
}

func TestDecodeDatagramNoAlloc(t *testing.T) {
	pkt := []byte{0, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 53, 'h', 'i'}
	m := map[string]int{string([]byte{atypIPv4, 1, 2, 3, 4, 0, 53}): 1}
	allocs := testing.AllocsPerRun(100, func() {
		_, key, _ := decodeDatagram(pkt)
		if m[string(key)] != 1 {
			panic("lookup failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("hot path allocates %v times per datagram", allocs)
	}
}
