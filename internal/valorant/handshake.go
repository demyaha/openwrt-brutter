// Package valorant finds a Valorant match from its connection handshake,
// measures free ports with the same handshake and moves the live mapping.
package valorant

import (
	"errors"
	"net/netip"

	"github.com/demyaha/brutter/internal/netx"
)

// Unreal's StatelessConnectHandler v3/4 handshake. Riot prefixes outgoing
// packets with 8 opaque bytes and incoming ones with 4; bit positions below
// are LSB-first from the start of the UDP payload.
const (
	outBase = 64
	inBase  = 32

	KindInitial         = 0
	KindChallenge       = 1
	KindResponse        = 2
	KindAck             = 3
	KindRestartResponse = 5

	// Handshake packets are small; gameplay never matches these header bits.
	maxHandshake = 400
	minHandshake = 48
	PortMin      = 7000
	PortMax      = 8000
)

// Header is the handshake part of a packet.
type Header struct {
	Kind, Seq, CID, Session uint8
	Restart                 bool
}

func bit(p []byte, i int) uint64 {
	if i/8 >= len(p) {
		return 0
	}
	return uint64(p[i/8]>>(i%8)) & 1
}

func bits(p []byte, start, width int) uint64 {
	var v uint64
	for i := 0; i < width; i++ {
		v |= bit(p, start+i) << i
	}
	return v
}

func setBits(p []byte, start, width int, v uint64) {
	for i := 0; i < width; i++ {
		b := (start + i) / 8
		mask := byte(1) << ((start + i) % 8)
		if v>>i&1 == 1 {
			p[b] |= mask
		} else {
			p[b] &^= mask
		}
	}
}

// ParseHeader reads a handshake header; length is the full UDP payload length
// when the captured payload may be cut short.
func ParseHeader(payload []byte, outgoing bool, length int) (Header, bool) {
	if length < minHandshake || length > maxHandshake || len(payload) < 16 {
		return Header{}, false
	}
	base := inBase
	if outgoing {
		base = outBase
	}
	if bits(payload, base+5, 1) != 1 || bits(payload, base+7, 8) != 3 || bits(payload, base+15, 8) != 4 {
		return Header{}, false
	}
	return Header{
		Session: uint8(bits(payload, base, 2)),
		CID:     uint8(bits(payload, base+2, 3)),
		Restart: bits(payload, base+6, 1) == 1,
		Kind:    uint8(bits(payload, base+23, 8)),
		Seq:     uint8(bits(payload, base+31, 8)),
	}, true
}

var errInitial = errors.New("expected a non-restarting Initial with zero authentication fields")

// Initial returns a copy of a zero-auth Initial with its counter set to seq.
// Anything that carries authentication data is refused.
func Initial(template []byte, seq uint8) ([]byte, error) {
	h, ok := ParseHeader(template, true, len(template))
	if !ok || h.Kind != KindInitial || h.Restart {
		return nil, errInitial
	}
	// Timestamp (bit 152) and cookie (bit 216) must be empty.
	for i := 151; i < 376 && i < len(template)*8; i++ {
		if bit(template, i) != 0 {
			return nil, errInitial
		}
	}
	out := append([]byte(nil), template...)
	setBits(out, 95, 8, uint64(seq))
	return out, nil
}

// IsChallenge matches the server's reply to our Initial.
func IsChallenge(payload []byte, seq, cid uint8) bool {
	h, ok := ParseHeader(payload, false, len(payload))
	return ok && h.Kind == KindChallenge && !h.Restart && h.Seq == seq && h.CID == cid
}

// RecoveryInitial builds a zero-auth Initial from the routing prefix of any
// outgoing packet of the session; nothing else of the game is reused.
func RecoveryInitial(outer []byte, cid uint8) ([]byte, error) {
	if len(outer) != 8 || cid > 7 {
		return nil, errors.New("invalid outer header")
	}
	t := make([]byte, 76)
	copy(t, outer)
	setBits(t, outBase+2, 3, uint64(cid))
	setBits(t, outBase+5, 1, 1)
	setBits(t, outBase+7, 8, 3)
	setBits(t, outBase+15, 8, 4)
	t[75] = 1
	return Initial(t, 0)
}

// Packet is a handshake packet between a LAN device and a public server.
type Packet struct {
	Header
	Out          bool
	Client       netip.Addr
	Server       netip.Addr
	SPort, DPort uint16 // device side, server side
	Payload      []byte
	Complete     bool
}

func gamePort(p uint16) bool { return p >= PortMin && p <= PortMax }

// Decode classifies an IPv4 packet; snap-length cuts are accepted for the
// header but a replayable Initial needs the complete packet.
func Decode(ip []byte) (Packet, bool) {
	u, err := netx.ParseIPv4UDP(ip, true)
	if err != nil {
		return Packet{}, false
	}
	var p Packet
	switch {
	case !netx.IsPublic(u.Src) && netx.IsPublic(u.Dst) && gamePort(u.DPort):
		p = Packet{Out: true, Client: u.Src, Server: u.Dst, SPort: u.SPort, DPort: u.DPort}
	case netx.IsPublic(u.Src) && !netx.IsPublic(u.Dst) && gamePort(u.SPort):
		p = Packet{Client: u.Dst, Server: u.Src, SPort: u.DPort, DPort: u.SPort}
	default:
		return Packet{}, false
	}
	h, ok := ParseHeader(u.Payload, p.Out, u.Length)
	if !ok {
		return Packet{}, false
	}
	p.Header, p.Payload, p.Complete = h, u.Payload, u.Complete
	return p, true
}
