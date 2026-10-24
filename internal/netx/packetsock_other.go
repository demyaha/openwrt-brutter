//go:build !linux

package netx

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/bpf"
)

const (
	EthAll = 0x0003
	EthIP  = 0x0800
)

type PacketSocket struct{}

var ErrNoPacket = errors.New("no packet")

func OpenPacket(string, bool, uint16, []bpf.Instruction) (*PacketSocket, error) {
	return nil, errLinux
}
func (p *PacketSocket) Read([]byte, time.Duration) (int, time.Time, error) {
	return 0, time.Time{}, errLinux
}
func (p *PacketSocket) Send([]byte, net.HardwareAddr) error { return errLinux }
func (p *PacketSocket) Close() error                        { return nil }
func SendRaw(string, []byte, [4]byte) error                 { return errLinux }
