package socket

import (
	"bytes"
	"net"
	"slices"

	"paqet/internal/pkg/hash"
)

// Addr is a peer address with a precomputed String. kcp-go calls String on
// every received packet; net.UDPAddr formats itself each time.
type Addr struct {
	IP   net.IP // 4 bytes for IPv4, 16 for IPv6; never modified
	Port int
	str  string
}

// NewAddr copies ip.
func NewAddr(ip net.IP, port int) *Addr {
	if ip4 := ip.To4(); ip4 != nil {
		ip = slices.Clone(ip4)
	} else {
		ip = slices.Clone(ip.To16())
	}
	return &Addr{IP: ip, Port: port, str: (&net.UDPAddr{IP: ip, Port: port}).String()}
}

// AddrOf converts a *net.UDPAddr or *Addr to an *Addr.
func AddrOf(a net.Addr) (*Addr, bool) {
	switch v := a.(type) {
	case *Addr:
		return v, v != nil
	case *net.UDPAddr:
		if v == nil {
			return nil, false
		}
		return NewAddr(v.IP, v.Port), true
	}
	return nil, false
}

func (a *Addr) Network() string { return "udp" }
func (a *Addr) String() string  { return a.str }

// maxCachedAddrs is only reached by scans or spoofed sources: clients use
// one source per connection.
const maxCachedAddrs = 4096

// addrCache shares one *Addr per source so steady traffic allocates nothing.
// It is not safe for concurrent use.
type addrCache map[uint64]*Addr

// get may be passed an ip that aliases a capture buffer.
func (c addrCache) get(ip []byte, port uint16) *Addr {
	key := hash.IPAddr(ip, port)
	if a, ok := c[key]; ok && a.Port == int(port) && bytes.Equal(a.IP, ip) {
		return a
	}
	if len(c) >= maxCachedAddrs {
		clear(c)
	}
	a := NewAddr(ip, int(port))
	c[key] = a
	return a
}
