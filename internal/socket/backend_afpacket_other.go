//go:build !linux

package socket

import (
	"errors"

	"paqet/internal/conf"
)

const afpacketSupported = false

var errNoAFPacket = errors.New("socket: AF_PACKET is only available on Linux")

func newAFPacketRx(*conf.Network, int) ([]rxSource, error) { return nil, errNoAFPacket }
func newAFPacketTx(*conf.Network) (txSink, error)          { return nil, errNoAFPacket }
