package conf

import (
	"fmt"
	"os"
	"paqet/internal/flog"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

type Conf struct {
	Role      string    `yaml:"role"`
	Log       Log       `yaml:"log"`
	Listen    Server    `yaml:"listen"`
	SOCKS5    []SOCKS5  `yaml:"socks5"`
	Forward   []Forward `yaml:"forward"`
	Network   Network   `yaml:"network"`
	Server    Server    `yaml:"server"`
	Transport Transport `yaml:"transport"`
}

func LoadFromFile(path string) (*Conf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf Conf

	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	// Unknown or misplaced keys are ignored, as before, but no longer
	// silently: they usually mean a setting the user thinks is applied is
	// not. They are not fatal, so existing configs keep starting.
	if keys := unknownKeys(data); len(keys) > 0 {
		flog.Warnf("ignoring unknown config keys (misspelled or at the wrong level?): %s", strings.Join(keys, ", "))
	}

	validRoles := []string{"client", "server"}
	if !slices.Contains(validRoles, conf.Role) {
		return nil, fmt.Errorf("role must be 'client' or 'server'")
	}

	conf.setDefaults()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}

func (c *Conf) setDefaults() {
	c.Log.setDefaults()
	c.Listen.setDefaults()
	for i := range c.SOCKS5 {
		c.SOCKS5[i].setDefaults()
	}
	for i := range c.Forward {
		c.Forward[i].setDefaults()
	}
	c.Network.setDefaults(c.Role)
	c.Server.setDefaults()
	c.Transport.setDefaults(c.Role)
}

func (c *Conf) validate() error {
	var allErrors []error

	allErrors = append(allErrors, c.Log.validate()...)
	if c.Role == "client" && len(c.SOCKS5) == 0 && len(c.Forward) == 0 {
		flog.Warnf("client mode enabled but no SOCKS5 or forward configurations found")
	}
	for i := range c.SOCKS5 {
		errs := c.SOCKS5[i].validate()
		for _, err := range errs {
			allErrors = append(allErrors, fmt.Errorf("socks5[%d] %v", i, err))
		}
	}

	for i := range c.Forward {
		errs := c.Forward[i].validate()
		for _, err := range errs {
			allErrors = append(allErrors, fmt.Errorf("forward[%d] %v", i, err))
		}
	}

	allErrors = append(allErrors, c.Network.validate()...)
	allErrors = append(allErrors, c.Transport.validate()...)
	c.warnOversizedPackets()
	if c.Role == "server" {
		allErrors = append(allErrors, c.Listen.validate()...)
	} else {
		allErrors = append(allErrors, c.Server.validate()...)
		if c.Server.Addr != nil {
			family, local := "IPv6", c.Network.IPv6.Addr
			if c.Server.Addr.IP.To4() != nil {
				family, local = "IPv4", c.Network.IPv4.Addr
			}
			if local == nil {
				allErrors = append(allErrors, fmt.Errorf("server address is %s, but the %s interface is not configured", family, family))
			}
		}
		if c.Transport.Conn > 1 && c.Network.Port != 0 {
			allErrors = append(allErrors, fmt.Errorf("only one connection is allowed when a client port is explicitly set"))
		}
	}
	return writeErr(allErrors)
}

// warnOversizedPackets warns when KCP packets cannot fit the interface MTU.
// Such frames are dropped by the kernel or NIC, which looks like a tunnel
// that connects but stalls as soon as real data flows.
func (c *Conf) warnOversizedPackets() {
	if c.Network.Interface == nil || c.Transport.KCP == nil {
		return
	}
	ifaceMTU := c.Network.Interface.MTU
	if ifaceMTU <= 0 {
		return
	}
	// Largest IP packet paqet sends: IPv6 (40) or IPv4 (20) plus a TCP
	// header with options (up to 40).
	ipHdr := 20
	if c.Network.IPv6.Addr != nil {
		ipHdr = 40
	}
	overhead := ipHdr + 40
	if mtu := c.Transport.KCP.MTU; mtu+overhead > ifaceMTU {
		flog.Warnf("transport.kcp.mtu %d plus %d bytes of IP/TCP headers exceeds the MTU of %s (%d): large packets will be dropped. Set transport.kcp.mtu to %d or less",
			mtu, overhead, c.Network.Interface.Name, ifaceMTU, ifaceMTU-overhead)
	}
}

func writeErr(allErrors []error) error {
	if len(allErrors) > 0 {
		var messages []string
		for _, err := range allErrors {
			messages = append(messages, err.Error())
		}
		return fmt.Errorf("validation failed:\n  - %s", strings.Join(messages, "\n  - "))
	}
	return nil
}
