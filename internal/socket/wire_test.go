package socket

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"

	"paqet/internal/conf"
)

// gopacketFrame is the encoder paqet used before the hand-rolled one,
// kept verbatim as the reference the new encoder must match byte for byte.
func gopacketFrame(t testing.TB, a *frameAddrs, s *tcpSegment, payload []byte) []byte {
	t.Helper()
	eth := layers.Ethernet{SrcMAC: a.srcMAC, DstMAC: a.dstMAC}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.srcPort), DstPort: layers.TCPPort(s.dstPort),
		FIN: s.flags.FIN, SYN: s.flags.SYN, RST: s.flags.RST, PSH: s.flags.PSH, ACK: s.flags.ACK,
		URG: s.flags.URG, ECE: s.flags.ECE, CWR: s.flags.CWR, NS: s.flags.NS,
		Window: 65535, Seq: s.seq, Ack: s.ack,
	}
	var ts [8]byte
	binary.BigEndian.PutUint32(ts[0:4], s.tsVal)
	binary.BigEndian.PutUint32(ts[4:8], s.tsEcr)
	if s.flags.SYN {
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts[:]},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		}
	} else {
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts[:]},
		}
	}
	var ip gopacket.SerializableLayer
	if len(a.dstIP) == 16 {
		ip6 := &layers.IPv6{Version: 6, TrafficClass: a.tos, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: a.srcIP, DstIP: a.dstIP}
		tcp.SetNetworkLayerForChecksum(ip6)
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = ip6
	} else {
		ip4 := &layers.IPv4{Version: 4, IHL: 5, TOS: a.tos, TTL: 64, Flags: layers.IPv4DontFragment, Protocol: layers.IPProtocolTCP, SrcIP: a.srcIP, DstIP: a.dstIP}
		tcp.SetNetworkLayerForChecksum(ip4)
		eth.EthernetType = layers.EthernetTypeIPv4
		ip = ip4
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, ip, &tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var (
	testSrcMAC = []byte{0x02, 0, 0, 0, 0, 1}
	testDstMAC = []byte{0x02, 0, 0, 0, 0, 2}
	testV4     = frameAddrs{srcMAC: testSrcMAC, dstMAC: testDstMAC, srcIP: net.IPv4(10, 0, 0, 1).To4(), dstIP: net.IPv4(10, 0, 0, 2).To4(), tos: 46 << 2}
	testV6     = frameAddrs{srcMAC: testSrcMAC, dstMAC: testDstMAC, srcIP: net.ParseIP("2001:db8::1"), dstIP: net.ParseIP("2001:db8::2"), tos: 46 << 2}
)

func allFlagCombos() []conf.TCPF {
	var out []conf.TCPF
	for v := range 1 << 9 {
		out = append(out, conf.TCPF{
			FIN: v&1 != 0, SYN: v&2 != 0, RST: v&4 != 0, PSH: v&8 != 0, ACK: v&16 != 0,
			URG: v&32 != 0, ECE: v&64 != 0, CWR: v&128 != 0, NS: v&256 != 0,
		})
	}
	return out
}

func TestEncodeMatchesGopacket(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 7, 31, 32, 33, 1000, 1349, 1350, 1500}
	for _, fam := range []struct {
		name string
		a    frameAddrs
	}{{"v4", testV4}, {"v6", testV6}} {
		for _, f := range allFlagCombos() {
			for _, n := range sizes {
				payload := make([]byte, n)
				for i := range payload {
					payload[i] = byte(i*131 + n)
				}
				s := tcpSegment{srcPort: 40000, dstPort: 9999, seq: 0xdeadbeef + uint32(n), ack: 0x01020304, tsVal: 0xa0b0c0d0, tsEcr: 0x11223344, flags: f}
				want := gopacketFrame(t, &fam.a, &s, payload)
				got := encodeFrame(nil, &fam.a, &s, payload)
				if !bytes.Equal(got, want) {
					t.Fatalf("%s flags=%+v len=%d: frame differs\n got %x\nwant %x", fam.name, f, n, got, want)
				}
			}
		}
	}
}

func TestEncodeReusesBuffer(t *testing.T) {
	buf := make([]byte, 0, 2048)
	s := tcpSegment{flags: conf.TCPF{PSH: true, ACK: true}}
	f := encodeFrame(buf, &testV4, &s, make([]byte, 1400))
	if &f[0] != &buf[:1][0] {
		t.Fatal("encodeFrame allocated although the buffer was large enough")
	}
}

func TestSendHandleSegmentPattern(t *testing.T) {
	// The sequence/ack/timestamp pattern is part of the wire fingerprint
	// and must not change.
	h := &SendHandle{srcPort: 1, time: 1_000_000}
	for i := uint32(1); i < 2000; i++ {
		f := conf.TCPF{PSH: true, ACK: true}
		if i%7 == 0 {
			f = conf.TCPF{SYN: true, ACK: i%2 == 0}
		}
		s := h.segment(9999, f)
		tsVal := h.time + i>>3
		if s.tsVal != tsVal {
			t.Fatalf("counter %d: tsVal %d", i, s.tsVal)
		}
		if f.SYN {
			wantAck := uint32(0)
			if f.ACK {
				wantAck = 1 + i&7 + 1
			}
			if s.seq != 1+i&7 || s.ack != wantAck || s.tsEcr != 0 {
				t.Fatalf("counter %d: SYN seq/ack/ecr %d/%d/%d", i, s.seq, s.ack, s.tsEcr)
			}
		} else {
			seq := h.time + i<<7
			if s.seq != seq || s.ack != seq-(i&0x3ff)+1400 || s.tsEcr != tsVal-(i%200+50) {
				t.Fatalf("counter %d: seq/ack/ecr %d/%d/%d", i, s.seq, s.ack, s.tsEcr)
			}
		}
	}
}

// gopacketDecode is the decoder paqet used before, for comparison.
func gopacketDecode(f []byte) (ip net.IP, srcPort, dstPort uint16, payload []byte, ok bool) {
	var (
		eth  layers.Ethernet
		dot1 layers.Dot1Q
		ip4  layers.IPv4
		ip6  layers.IPv6
		tcp  layers.TCP
	)
	p := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1, &ip4, &ip6, &tcp)
	p.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	if err := p.DecodeLayers(f, &decoded); err != nil {
		return
	}
	for _, t := range decoded {
		switch t {
		case layers.LayerTypeIPv4:
			ip = ip4.SrcIP
		case layers.LayerTypeIPv6:
			ip = ip6.SrcIP
		case layers.LayerTypeTCP:
			srcPort, dstPort, payload, ok = uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Payload, true
		}
	}
	return ip, srcPort, dstPort, payload, ok && ip != nil
}

func TestDecodeMatchesGopacket(t *testing.T) {
	for _, a := range []frameAddrs{testV4, testV6} {
		for _, syn := range []bool{false, true} {
			for _, n := range []int{0, 1, 100, 1350} {
				payload := bytes.Repeat([]byte{0xab}, n)
				s := tcpSegment{srcPort: 40001, dstPort: 9999, flags: conf.TCPF{SYN: syn, PSH: !syn, ACK: true}}
				f := encodeFrame(nil, &a, &s, payload)

				var d decodedFrame
				if !decodeFrame(f, &d) {
					t.Fatalf("decode failed for len %d", n)
				}
				ip, sp, dp, pl, ok := gopacketDecode(f)
				if !ok || !net.IP(d.srcIP).Equal(ip) || d.srcPort != sp || d.dstPort != dp || !bytes.Equal(d.payload, pl) {
					t.Fatalf("mismatch: got %v:%d->%d %d bytes, gopacket %v:%d->%d %d bytes", net.IP(d.srcIP), d.srcPort, d.dstPort, len(d.payload), ip, sp, dp, len(pl))
				}
			}
		}
	}
}

func TestDecodeVLAN(t *testing.T) {
	s := tcpSegment{srcPort: 1234, dstPort: 9999, flags: conf.TCPF{PSH: true, ACK: true}}
	plain := encodeFrame(nil, &testV4, &s, []byte("hello"))
	tagged := append(append(append([]byte{}, plain[:12]...), 0x81, 0x00, 0x00, 0x2a), plain[12:]...)
	var d decodedFrame
	if !decodeFrame(tagged, &d) || string(d.payload) != "hello" || d.srcPort != 1234 {
		t.Fatalf("VLAN frame not decoded: %+v", d)
	}
}

func TestDecodeRejects(t *testing.T) {
	s := tcpSegment{srcPort: 1, dstPort: 9999, flags: conf.TCPF{PSH: true, ACK: true}}
	good := encodeFrame(nil, &testV4, &s, []byte("data"))
	cases := map[string]func([]byte) []byte{
		"short":       func(f []byte) []byte { return f[:10] },
		"arp":         func(f []byte) []byte { f[12], f[13] = 0x08, 0x06; return f },
		"udp":         func(f []byte) []byte { f[ethHdrLen+9] = 17; return f },
		"fragment":    func(f []byte) []byte { f[ethHdrLen+6] = 0x20; return f }, // MF
		"frag-offset": func(f []byte) []byte { f[ethHdrLen+7] = 1; return f },
		"bad-ihl":     func(f []byte) []byte { f[ethHdrLen] = 0x44; return f },
		"bad-doff":    func(f []byte) []byte { f[ethHdrLen+ipv4HdrLen+12] = 0x40; return f },
		"truncated":   func(f []byte) []byte { return f[:ethHdrLen+ipv4HdrLen+10] },
	}
	for name, mut := range cases {
		f := mut(bytes.Clone(good))
		var d decodedFrame
		if decodeFrame(f, &d) {
			t.Errorf("%s: frame accepted", name)
		}
	}
}

func TestCaptureFilter(t *testing.T) {
	vm, err := bpf.NewVM(captureProgram(9999, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := captureFilter(9999, true); err != nil {
		t.Fatalf("inbound program does not assemble: %v", err)
	}
	frame := func(a frameAddrs, dport uint16) []byte {
		s := tcpSegment{srcPort: 5555, dstPort: dport, flags: conf.TCPF{PSH: true, ACK: true}}
		return encodeFrame(nil, &a, &s, []byte("x"))
	}
	withIPOpts := func() []byte {
		// IPv4 header with 4 bytes of options (IHL 6).
		f := frame(testV4, 9999)
		out := append([]byte{}, f[:ethHdrLen+ipv4HdrLen]...)
		out = append(out, 1, 1, 1, 0)
		out = append(out, f[ethHdrLen+ipv4HdrLen:]...)
		out[ethHdrLen] = 0x46
		return out
	}
	cases := []struct {
		name string
		f    []byte
		want bool
	}{
		{"v4 match", frame(testV4, 9999), true},
		{"v4 other port", frame(testV4, 9998), false},
		{"v6 match", frame(testV6, 9999), true},
		{"v6 other port", frame(testV6, 1), false},
		{"v4 ip options", withIPOpts(), true},
		{"v4 udp", func() []byte { f := frame(testV4, 9999); f[ethHdrLen+9] = 17; return f }(), false},
		{"v4 fragment", func() []byte { f := frame(testV4, 9999); f[ethHdrLen+6] = 0x20; return f }(), false},
		{"v6 udp", func() []byte { f := frame(testV6, 9999); f[ethHdrLen+6] = 17; return f }(), false},
		{"arp", func() []byte { f := frame(testV4, 9999); f[12], f[13] = 0x08, 0x06; return f }(), false},
	}
	for _, c := range cases {
		n, err := vm.Run(c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := n > 0; got != c.want {
			t.Errorf("%s: accepted=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestAddrCache(t *testing.T) {
	c := make(addrCache)

	buf := []byte{10, 0, 0, 1}
	a := c.get(buf, 1000)
	buf[3] = 2 // the capture buffer is reused; the cached address must not change
	if got := a.String(); got != "10.0.0.1:1000" {
		t.Fatalf("cached address aliased the capture buffer: %s", got)
	}
	if b := c.get([]byte{10, 0, 0, 1}, 1000); b != a {
		t.Fatal("same source should reuse the cached address")
	}
	if d := c.get([]byte{10, 0, 0, 1}, 1001); d == a || d.Port != 1001 {
		t.Fatal("different port must not hit the cache")
	}

	// IPv6 keys are XOR-folded and can collide; equality must be verified.
	x := net.ParseIP("2001:db8::1")
	y := net.ParseIP("2001:db8::1:0:0:0:0") // differs only in a folded half
	ax, ay := c.get(x, 53), c.get(y, 53)
	if !ax.IP.Equal(x) || !ay.IP.Equal(y) {
		t.Fatalf("collision returned the wrong address: %v %v", ax, ay)
	}
}

func TestAddrCacheBounded(t *testing.T) {
	c := make(addrCache)
	for i := range maxCachedAddrs + 10 {
		c.get([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}, 1)
	}
	if len(c) > maxCachedAddrs {
		t.Fatalf("cache grew past bound: %d", len(c))
	}
}

func TestAddrStringMatchesUDPAddr(t *testing.T) {
	for _, s := range []string{"10.0.0.1:9999", "[2001:db8::1]:443"} {
		u, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			t.Fatal(err)
		}
		if got := NewAddr(u.IP, u.Port).String(); got != u.String() {
			t.Fatalf("Addr %q, UDPAddr %q", got, u.String())
		}
	}
	// IPv4 in 16-byte form must format, hash and compare like 4-byte IPv4,
	// or a client would reject its server's packets.
	a := NewAddr(net.IPv4(1, 2, 3, 4), 5)
	b := make(addrCache).get([]byte{1, 2, 3, 4}, 5)
	if a.String() != b.String() || len(a.IP) != 4 {
		t.Fatalf("IPv4 forms differ: %q (%d bytes) vs %q", a, len(a.IP), b)
	}
}

func BenchmarkEncode(b *testing.B) {
	buf := make([]byte, 0, 2048)
	payload := make([]byte, 1350)
	s := tcpSegment{srcPort: 1, dstPort: 2, flags: conf.TCPF{PSH: true, ACK: true}}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := range b.N {
		s.seq = uint32(i)
		buf = encodeFrame(buf, &testV4, &s, payload)
	}
}

func BenchmarkDecode(b *testing.B) {
	s := tcpSegment{srcPort: 1, dstPort: 2, flags: conf.TCPF{PSH: true, ACK: true}}
	f := encodeFrame(nil, &testV4, &s, make([]byte, 1350))
	var d decodedFrame
	b.ReportAllocs()
	for range b.N {
		if !decodeFrame(f, &d) {
			b.Fatal("decode failed")
		}
	}
}

func ExampleAddr() {
	fmt.Println(NewAddr(net.IPv4(192, 0, 2, 1), 9999))
	// Output: 192.0.2.1:9999
}
