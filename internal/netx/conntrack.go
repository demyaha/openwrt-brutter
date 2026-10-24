package netx

import (
	"errors"
	"net/netip"
)

// Flow is one IPv4 UDP conntrack entry, as seen from the LAN device.
type Flow struct {
	ID           uint32
	Client       netip.Addr // original source: the LAN device
	Server       netip.Addr // original destination
	Public       netip.Addr // reply destination: the WAN address after NAT
	SPort        uint16
	DPort        uint16
	External     uint16 // reply destination port: the device's port after NAT
	Packets      uint64
	ReplyPackets uint64
	Assured      bool
}

// Tuple identifies the device's side of a flow, independent of NAT.
type Tuple struct {
	Client, Server netip.Addr
	SPort, DPort   uint16
}

func (f Flow) Tuple() Tuple { return Tuple{f.Client, f.Server, f.SPort, f.DPort} }

// Endpoint is a game server address.
type Endpoint struct {
	Server netip.Addr
	Port   uint16
}

func (f Flow) Endpoint() Endpoint { return Endpoint{f.Server, f.DPort} }

// Table reads and deletes UDP conntrack entries.
type Table interface {
	Flows() ([]Flow, error)
	Delete(f Flow) error
	Lookup(t Tuple) (Flow, bool, error)
}

// ErrChanged means the entry was replaced since it was observed.
var ErrChanged = errors.New("connection entry changed")

// Occupied lists the WAN ports already mapped toward an endpoint.
func Occupied(flows []Flow, public netip.Addr, ep Endpoint) map[uint16]bool {
	busy := map[uint16]bool{}
	for _, f := range flows {
		if f.Public == public && f.Server == ep.Server && f.DPort == ep.Port {
			busy[f.External] = true
		}
	}
	return busy
}
