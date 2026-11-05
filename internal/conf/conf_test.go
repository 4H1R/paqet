package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestRejectsMisplacedKeys(t *testing.T) {
	// "conn" and "sockbuf" under kcp were previously ignored silently.
	cfg := `role: "server"
transport:
  protocol: "kcp"
  kcp:
    key: "k"
    conn: 8
    sockbuf: 8388608
`
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestExamplesAreStrictlyValid(t *testing.T) {
	for _, name := range []string{"client.yaml.example", "server.yaml.example"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "example", name))
		if err != nil {
			t.Fatal(err)
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
