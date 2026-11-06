package socket

import (
	"bytes"
	"net"
	"slices"

	"paqet/internal/pkg/hash"
)

// Addr is a peer address whose string form is computed once.
//
// kcp-go's Listener looks sessions up by addr.String() for every received
// packet, and client sessions compare addr.String() against the remote
// address when the address is not a *net.UDPAddr. net.UDPAddr formats
// itself on every call (3 allocations); Addr returns a cached string.
type Addr struct {
	IP   net.IP // 4 bytes for IPv4, 16 for IPv6; never modified
	Port int
	str  string
}

// NewAddr returns an Addr for ip and port. ip is copied.
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

// maxCachedAddrs bounds the source address cache. Clients use one source
// per connection, so this is only reached by scans or spoofed traffic.
const maxCachedAddrs = 4096

// addrCache hands out one shared *Addr per source so steady traffic from a
// peer allocates nothing. It is not safe for concurrent use.
type addrCache map[uint64]*Addr

// get returns the cached address for ip (which may alias a capture buffer)
// and port, creating it if needed.
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
