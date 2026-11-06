package kcp

import (
	"fmt"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"paqet/internal/conf"
	"paqet/internal/socket"
	"paqet/internal/tnet"
)

func Dial(addr *net.UDPAddr, cfg *conf.KCP, netCfg conf.Network) (tnet.Conn, error) {
	nCfg := netCfg
	packetConn, err := socket.New(&nCfg)
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to create packetconn: %w", err)
	}

	// The cached-string address lets kcp-go match each received packet's
	// source with a string compare instead of formatting addresses.
	conn, err := dialOn(socket.NewAddr(addr.IP, addr.Port), cfg, packetConn)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	conn.PacketConn = packetConn
	return conn, nil
}

// dialOn opens a KCP+smux client session over an existing packet conn.
func dialOn(addr net.Addr, cfg *conf.KCP, pc net.PacketConn) (*Conn, error) {
	sess, err := kcp.NewConn2(addr, cfg.Block, cfg.Dshard, cfg.Pshard, pc)
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to dial connection: %w", err)
	}
	aplConf(sess, cfg)

	mux, err := smux.Client(sess, smuxConf(cfg))
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("kcp: failed to create smux session: %w", err)
	}

	return &Conn{UDPSession: sess, Session: mux}, nil
}
