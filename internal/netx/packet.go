// Package netx holds the small amount of raw networking Brutter needs:
// IPv4/UDP datagrams, conntrack, nftables, kernel receive timestamps.
package netx

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Checksum is the Internet checksum of data.
func Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// Datagram builds an IPv4/UDP packet with valid checksums.
func Datagram(src, dst netip.Addr, sport, dport uint16, payload []byte, ident uint16) []byte {
	s, d := src.As4(), dst.As4()
	udpLen := 8 + len(payload)
	packet := make([]byte, 20+udpLen)
	ip := packet[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(packet)))
	binary.BigEndian.PutUint16(ip[4:], ident)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	binary.BigEndian.PutUint16(ip[10:], Checksum(ip))
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	pseudo := make([]byte, 0, 12+udpLen)
	pseudo = append(pseudo, s[:]...)
	pseudo = append(pseudo, d[:]...)
	pseudo = append(pseudo, 0, 17, byte(udpLen>>8), byte(udpLen))
	pseudo = append(pseudo, udp...)
	sum := Checksum(pseudo)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return packet
}

// UDP is a parsed IPv4/UDP packet. Payload may be cut short by a capture's
// snap length; Complete says whether it was.
type UDP struct {
	Src, Dst     netip.Addr
	SPort, DPort uint16
	Length       int // UDP payload length from the header
	Payload      []byte
	Complete     bool
}

var errPacket = errors.New("not an unfragmented IPv4/UDP packet")

// ParseIPv4UDP parses an IPv4 packet; truncated payloads are allowed only
// when partial is true.
func ParseIPv4UDP(p []byte, partial bool) (UDP, error) {
	var u UDP
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
		return u, errPacket
	}
	ihl := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if ihl < 20 || total < ihl+8 || len(p) < ihl+8 || (total > len(p) && !partial) {
		return u, errPacket
	}
	if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
		return u, errPacket
	}
	length := int(binary.BigEndian.Uint16(p[ihl+4:]))
	if length < 8 || length != total-ihl {
		return u, errPacket
	}
	end := total
	if end > len(p) {
		end = len(p)
	}
	u.Src = netip.AddrFrom4([4]byte(p[12:16]))
	u.Dst = netip.AddrFrom4([4]byte(p[16:20]))
	u.SPort = binary.BigEndian.Uint16(p[ihl:])
	u.DPort = binary.BigEndian.Uint16(p[ihl+2:])
	u.Length = length - 8
	u.Payload = p[ihl+8 : end]
	u.Complete = len(u.Payload) == u.Length
	return u, nil
}

// ParseEthernet strips an Ethernet header carrying IPv4.
func ParseEthernet(frame []byte) ([]byte, bool) {
	if len(frame) < 14 || frame[12] != 0x08 || frame[13] != 0x00 {
		return nil, false
	}
	return frame[14:], true
}

// IsPublic reports whether a is a routable unicast IPv4 address.
func IsPublic(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() &&
		!sharedSpace.Contains(a) && !benchmark.Contains(a) && !a.IsLinkLocalUnicast()
}

var (
	sharedSpace = netip.MustParsePrefix("100.64.0.0/10")
	benchmark   = netip.MustParsePrefix("198.18.0.0/15")
)
