package socket

import (
	"golang.org/x/net/bpf"
)

// packetOutgoing is PACKET_OUTGOING from linux/if_packet.h.
const packetOutgoing = 4

// captureFilter accepts what decodeFrame accepts, sent to dstPort.
// inboundOnly also rejects frames the host sent, using a Linux-only
// ancillary field. AF_PACKET strips VLAN tags before filtering.
func captureFilter(dstPort uint16, inboundOnly bool) ([]bpf.RawInstruction, error) {
	return bpf.Assemble(captureProgram(dstPort, inboundOnly))
}

func captureProgram(dstPort uint16, inboundOnly bool) []bpf.Instruction {
	// Jump offsets below are relative to the instruction after the jump.
	prog := []bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 12, Size: 2}, // ethertype
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv4, SkipFalse: 7}, // -> 9
		// IPv4
		/* 2 */ bpf.LoadAbsolute{Off: ethHdrLen + 9, Size: 1}, // protocol
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: 11}, // -> reject
		/* 4 */ bpf.LoadAbsolute{Off: ethHdrLen + 6, Size: 2}, // flags + fragment offset
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x3fff, SkipTrue: 9}, // MF or offset -> reject
		/* 6 */ bpf.LoadMemShift{Off: ethHdrLen}, // X = IHL*4
		/* 7 */ bpf.LoadIndirect{Off: ethHdrLen + 2, Size: 2}, // TCP dst port
		/* 8 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 5, SkipFalse: 6}, // -> accept / reject
		// IPv6
		/* 9 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv6, SkipFalse: 5}, // -> reject
		/* 10 */ bpf.LoadAbsolute{Off: ethHdrLen + 6, Size: 1}, // next header
		/* 11 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: 3}, // -> reject
		/* 12 */ bpf.LoadAbsolute{Off: ethHdrLen + ipv6HdrLen + 2, Size: 2}, // TCP dst port
		/* 13 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipFalse: 1}, // -> reject
		/* 14 accept */ bpf.RetConstant{Val: 0x40000},
		/* 15 reject */ bpf.RetConstant{Val: 0},
	}
	if inboundOnly {
		// Relative jumps above are unaffected; reject is now at 17.
		prog = append([]bpf.Instruction{
			bpf.LoadExtension{Num: bpf.ExtType},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: packetOutgoing, SkipTrue: 15},
		}, prog...)
	}
	return prog
}
