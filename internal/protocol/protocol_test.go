package protocol

import (
	"bytes"
	"reflect"
	"testing"

	"paqet/internal/conf"
	"paqet/internal/tnet"
)

func TestRoundTrip(t *testing.T) {
	cases := []Proto{
		{Type: PPING},
		{Type: PPONG},
		{Type: PTCP, Addr: &tnet.Addr{Host: "example.com", Port: 443}},
		{Type: PUDP, Addr: &tnet.Addr{Host: "2001:db8::1", Port: 53}},
		{Type: PTCPF, TCPF: []conf.TCPF{{PSH: true, ACK: true}, {SYN: true}, {NS: true, CWR: true}}},
	}
	for _, want := range cases {
		var buf bytes.Buffer
		if err := want.Write(&buf); err != nil {
			t.Fatalf("write %d: %v", want.Type, err)
		}
		var got Proto
		if err := got.Read(&buf); err != nil {
			t.Fatalf("read %d: %v", want.Type, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
		}
	}
}

func TestRejectsBadInput(t *testing.T) {
	bad := [][]byte{
		{0x00, VERSION, PPING, 0, 0},           // bad magic
		{MAGIC, 0x7f, PPING, 0, 0},             // bad version
		{MAGIC, VERSION, PTCP, 0, 2, 0, 0},     // truncated address
		{MAGIC, VERSION, PTCP, 0xff, 0xff},     // body too long
		{MAGIC, VERSION, 0x7e, 0, 0},           // unknown type
		{MAGIC, VERSION, PTCPF, 0, 2, 5, 0x00}, // tcpf count mismatch
	}
	for i, b := range bad {
		var p Proto
		if err := p.Read(bytes.NewReader(b)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
