package socket

import (
	"encoding/binary"
	"math/bits"

	"paqet/internal/conf"
)

// Frame encoding and decoding for the hot path. paqet only builds Ethernet
// + IPv4/IPv6 + TCP frames with two fixed option layouts, so a general
// packet library is pure overhead. wire_test.go checks the output stays
// byte-for-byte identical to the gopacket encoder this replaced.

const (
	ethHdrLen    = 14
	ipv4HdrLen   = 20
	ipv6HdrLen   = 40
	tcpHdrLenSYN = 40 // 20 + MSS(4) SACKPermitted(2) TS(10) NOP(1) WS(3)
	tcpHdrLen    = 32 // 20 + NOP NOP TS(10)

	maxHdrLen = ethHdrLen + ipv6HdrLen + tcpHdrLenSYN

	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8

	protoTCP = 6
)

type tcpSegment struct {
	srcPort, dstPort uint16
	seq, ack         uint32
	tsVal, tsEcr     uint32
	flags            conf.TCPF
}

// frameAddrs holds a frame's addresses. srcIP and dstIP are both 4 bytes
// (IPv4) or both 16 bytes (IPv6).
type frameAddrs struct {
	srcMAC, dstMAC []byte
	srcIP, dstIP   []byte
	tos            uint8
}

// encodeFrame builds the frame in buf, growing it if needed.
func encodeFrame(buf []byte, a *frameAddrs, t *tcpSegment, payload []byte) []byte {
	v6 := len(a.dstIP) == 16
	ipLen := ipv4HdrLen
	if v6 {
		ipLen = ipv6HdrLen
	}
	tLen := tcpHdrLen
	if t.flags.SYN {
		tLen = tcpHdrLenSYN
	}
	total := ethHdrLen + ipLen + tLen + len(payload)
	if cap(buf) < total {
		buf = make([]byte, total)
	}
	b := buf[:total]

	// Frames always exceed Ethernet's 60 byte minimum; no padding needed.
	copy(b[0:6], a.dstMAC)
	copy(b[6:12], a.srcMAC)

	ip := b[ethHdrLen : ethHdrLen+ipLen]
	tcp := b[ethHdrLen+ipLen : ethHdrLen+ipLen+tLen]
	copy(b[ethHdrLen+ipLen+tLen:], payload)
	segLen := tLen + len(payload)

	var pseudo uint32
	if v6 {
		binary.BigEndian.PutUint16(b[12:], etherTypeIPv6)
		ip[0] = 6<<4 | a.tos>>4
		ip[1] = a.tos << 4
		ip[2], ip[3] = 0, 0
		binary.BigEndian.PutUint16(ip[4:], uint16(segLen))
		ip[6] = protoTCP
		ip[7] = 64 // hop limit
		copy(ip[8:24], a.srcIP)
		copy(ip[24:40], a.dstIP)
		pseudo = sum16(0, ip[8:40]) + protoTCP + uint32(segLen)
	} else {
		binary.BigEndian.PutUint16(b[12:], etherTypeIPv4)
		ip[0] = 4<<4 | ipv4HdrLen/4
		ip[1] = a.tos
		binary.BigEndian.PutUint16(ip[2:], uint16(ipv4HdrLen+segLen))
		ip[4], ip[5] = 0, 0    // id
		ip[6], ip[7] = 0x40, 0 // don't fragment
		ip[8] = 64             // ttl
		ip[9] = protoTCP
		ip[10], ip[11] = 0, 0
		copy(ip[12:16], a.srcIP)
		copy(ip[16:20], a.dstIP)
		binary.BigEndian.PutUint16(ip[10:], fold(sum16(0, ip)))
		pseudo = sum16(0, ip[12:20]) + protoTCP + uint32(segLen)
	}

	binary.BigEndian.PutUint16(tcp[0:], t.srcPort)
	binary.BigEndian.PutUint16(tcp[2:], t.dstPort)
	binary.BigEndian.PutUint32(tcp[4:], t.seq)
	binary.BigEndian.PutUint32(tcp[8:], t.ack)
	tcp[12] = byte(tLen/4) << 4
	if t.flags.NS {
		tcp[12] |= 1
	}
	tcp[13] = tcpFlagByte(t.flags)
	tcp[14], tcp[15] = 0xff, 0xff // window
	tcp[16], tcp[17] = 0, 0       // checksum
	tcp[18], tcp[19] = 0, 0       // urgent pointer
	o := tcp[20:]
	if t.flags.SYN {
		o[0], o[1], o[2], o[3] = 2, 4, 0x05, 0xb4 // MSS 1460
		o[4], o[5] = 4, 2                         // SACK permitted
		o[6], o[7] = 8, 10                        // timestamps
		binary.BigEndian.PutUint32(o[8:], t.tsVal)
		binary.BigEndian.PutUint32(o[12:], t.tsEcr)
		o[16] = 1                     // NOP
		o[17], o[18], o[19] = 3, 3, 8 // window scale 8
	} else {
		o[0], o[1] = 1, 1  // NOP NOP
		o[2], o[3] = 8, 10 // timestamps
		binary.BigEndian.PutUint32(o[4:], t.tsVal)
		binary.BigEndian.PutUint32(o[8:], t.tsEcr)
	}
	seg := b[ethHdrLen+ipLen:]
	binary.BigEndian.PutUint16(tcp[16:], fold(sum16(pseudo, seg)))
	return b
}

func tcpFlagByte(f conf.TCPF) byte {
	var v byte
	if f.FIN {
		v |= 1 << 0
	}
	if f.SYN {
		v |= 1 << 1
	}
	if f.RST {
		v |= 1 << 2
	}
	if f.PSH {
		v |= 1 << 3
	}
	if f.ACK {
		v |= 1 << 4
	}
	if f.URG {
		v |= 1 << 5
	}
	if f.ECE {
		v |= 1 << 6
	}
	if f.CWR {
		v |= 1 << 7
	}
	return v
}

// sum16 adds b's big-endian 16-bit words to a ones' complement sum, 32 bytes
// at a time.
func sum16(init uint32, b []byte) uint32 {
	s := uint64(init)
	var c uint64
	for len(b) >= 32 {
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[0:]), 0)
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[8:]), c)
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[16:]), c)
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b[24:]), c)
		s += c
		b = b[32:]
	}
	for len(b) >= 8 {
		s, c = bits.Add64(s, binary.BigEndian.Uint64(b), 0)
		s += c
		b = b[8:]
	}
	for len(b) >= 2 {
		s, c = bits.Add64(s, uint64(binary.BigEndian.Uint16(b)), 0)
		s += c
		b = b[2:]
	}
	if len(b) == 1 {
		s, c = bits.Add64(s, uint64(b[0])<<8, 0)
		s += c
	}
	s = s>>32 + s&0xffffffff
	s = s>>32 + s&0xffffffff
	return uint32(s)
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

type decodedFrame struct {
	srcIP   []byte // 4 or 16 bytes, aliases the frame
	srcPort uint16
	dstPort uint16
	payload []byte // aliases the frame
}

// decodeFrame parses TCP over IPv4/IPv6 over Ethernet, skipping VLAN tags.
// It rejects fragments and IPv6 extension headers. Slices in d alias f.
func decodeFrame(f []byte, d *decodedFrame) bool {
	if len(f) < ethHdrLen {
		return false
	}
	et := binary.BigEndian.Uint16(f[12:])
	p := f[ethHdrLen:]
	for i := 0; i < 2 && (et == etherTypeVLAN || et == etherTypeQinQ); i++ {
		if len(p) < 4 {
			return false
		}
		et = binary.BigEndian.Uint16(p[2:])
		p = p[4:]
	}

	switch et {
	case etherTypeIPv4:
		if len(p) < ipv4HdrLen || p[0]>>4 != 4 || p[9] != protoTCP {
			return false
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < ipv4HdrLen || ihl > len(p) {
			return false
		}
		if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 { // MF flag or fragment offset
			return false
		}
		tot := int(binary.BigEndian.Uint16(p[2:]))
		switch {
		case tot == 0: // segmentation offload leaves the length unset
			tot = len(p)
		case tot < ihl:
			return false
		case tot > len(p): // truncated capture
			tot = len(p)
		}
		d.srcIP = p[12:16]
		p = p[ihl:tot]
	case etherTypeIPv6:
		if len(p) < ipv6HdrLen || p[0]>>4 != 6 || p[6] != protoTCP {
			return false
		}
		pl := int(binary.BigEndian.Uint16(p[4:]))
		if pl == 0 { // jumbogram
			return false
		}
		d.srcIP = p[8:24]
		p = p[ipv6HdrLen:]
		if pl < len(p) {
			p = p[:pl]
		}
	default:
		return false
	}

	if len(p) < 20 {
		return false
	}
	off := int(p[12]>>4) * 4
	if off < 20 || off > len(p) {
		return false
	}
	d.srcPort = binary.BigEndian.Uint16(p[0:])
	d.dstPort = binary.BigEndian.Uint16(p[2:])
	d.payload = p[off:]
	return true
}
