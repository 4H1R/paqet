//go:build !windows

package socket

import "paqet/internal/conf"

func newPcapTx(cfg *conf.Network) (txSink, error) { return newPcapPacketTx(cfg) }
