package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// paqctl-generated configs put conn and sockbuf under kcp. They must keep
// loading (master ignored those keys) and the keys must be reported.
const misplacedCfg = `role: "server"
listen:
  addr: ":9999"
network:
  interface: "lo"
  ipv4:
    addr: "127.0.0.1:9999"
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag: ["PA"]
    typo_flag: ["S"]
transport:
  protocol: "kcp"
  kcp:
    key: "k"
    conn: 8
    sockbuf: 8388608
`

func TestUnknownKeysReportedWithPaths(t *testing.T) {
	got := unknownKeys([]byte(misplacedCfg))
	want := []string{"network.tcp.typo_flag", "transport.kcp.conn", "transport.kcp.sockbuf"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unknownKeys = %v, want %v", got, want)
	}
}

func TestUnknownKeysAreNotFatal(t *testing.T) {
	var c Conf
	if err := yaml.Unmarshal([]byte(misplacedCfg), &c); err != nil {
		t.Fatalf("lenient parse must accept unknown keys: %v", err)
	}
	if c.Transport.KCP.Key != "k" || c.Listen.Addr_ != ":9999" {
		t.Fatalf("known keys not decoded: %+v", c)
	}
}

func TestUnknownKeysInLists(t *testing.T) {
	cfg := "role: client\nforward:\n  - listen: \":1\"\n    target: \"x:1\"\n    protcol: tcp\n"
	if got := unknownKeys([]byte(cfg)); len(got) != 1 || got[0] != "forward[0].protcol" {
		t.Fatalf("got %v", got)
	}
}

func TestExamplesHaveNoUnknownKeys(t *testing.T) {
	for _, name := range []string{"client.yaml.example", "server.yaml.example"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "example", name))
		if err != nil {
			t.Fatal(err)
		}
		if keys := unknownKeys(data); len(keys) > 0 {
			t.Errorf("%s: unknown keys %v", name, keys)
		}
		var c Conf
		if err := yaml.UnmarshalWithOptions(data, &c, yaml.DisallowUnknownField()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKCPInit(t *testing.T) {
	k := &KCP{Key: "secret"}
	if err := k.Init("client"); err != nil {
		t.Fatal(err)
	}
	if k.Mode != "fast" || k.Block == nil || k.Smuxkalive == 0 {
		t.Fatalf("defaults not applied: %+v", k)
	}
}

func TestDSCP(t *testing.T) {
	var n Network
	n.setDefaults("client")
	if n.DSCP != defaultDSCP {
		t.Fatalf("default DSCP = %d, want %d", n.DSCP, defaultDSCP)
	}
	zero := 0
	n = Network{DSCP_: &zero}
	n.setDefaults("client")
	if n.DSCP != 0 {
		t.Fatalf("explicit dscp 0 must be honored, got %d", n.DSCP)
	}
}
