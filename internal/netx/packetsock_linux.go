package netx

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	EthAll = 0x0003
	EthIP  = 0x0800
)

// PacketSocket is an AF_PACKET socket on one interface behind a classic BPF
// filter. Raw sockets see Ethernet frames, datagram sockets see IP packets.
type PacketSocket struct {
	fd      int
	ifindex int
	oob     []byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// OpenPacket opens an AF_PACKET socket bound to iface.
func OpenPacket(iface string, raw bool, protocol uint16, filter []bpf.Instruction) (*PacketSocket, error) {
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	kind := unix.SOCK_DGRAM
	if raw {
		kind = unix.SOCK_RAW
	}
	fd, err := unix.Socket(unix.AF_PACKET, kind|unix.SOCK_CLOEXEC, int(htons(protocol)))
	if err != nil {
		return nil, err
	}
	p := &PacketSocket{fd: fd, ifindex: link.Index, oob: make([]byte, 128)}
	fail := func(err error) (*PacketSocket, error) {
		unix.Close(fd)
		return nil, err
	}
	if filter != nil {
		program, err := bpf.Assemble(filter)
		if err != nil {
			return fail(err)
		}
		sock := make([]unix.SockFilter, len(program))
		for i, ins := range program {
			sock[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		fprog := unix.SockFprog{Len: uint16(len(sock)), Filter: &sock[0]}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
			return fail(err)
		}
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(protocol), Ifindex: link.Index}); err != nil {
		return fail(err)
	}
	// Anything queued before the filter took effect is dropped by draining.
	buf := make([]byte, 64)
	for {
		if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
			break
		}
	}
	return p, nil
}

// ErrNoPacket means the read timed out.
var ErrNoPacket = errors.New("no packet")

// Read waits up to timeout for one packet and its kernel arrival time.
func (p *PacketSocket) Read(buf []byte, timeout time.Duration) (int, time.Time, error) {
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(p.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, time.Time{}, err
	}
	n, oobn, _, _, err := unix.Recvmsg(p.fd, buf, p.oob, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, time.Time{}, ErrNoPacket
		}
		return 0, time.Time{}, err
	}
	return n, arrival(p.oob[:oobn]), nil
}

// Send transmits an IP packet on a datagram socket; mac is nil on PPP links.
func (p *PacketSocket) Send(packet []byte, mac net.HardwareAddr) error {
	addr := &unix.SockaddrLinklayer{Protocol: htons(EthIP), Ifindex: p.ifindex}
	if len(mac) == 6 {
		addr.Halen = 6
		copy(addr.Addr[:], mac)
	}
	return unix.Sendto(p.fd, packet, 0, addr)
}

func (p *PacketSocket) Close() error { return unix.Close(p.fd) }

// SendRaw writes a complete IPv4 packet (header included) out of iface, so it
// passes through conntrack and NAT like a forwarded packet would.
func SendRaw(iface string, packet []byte, dst [4]byte) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}
	if err := unix.BindToDevice(fd, iface); err != nil {
		return err
	}
	return unix.Sendto(fd, packet, 0, &unix.SockaddrInet4{Addr: dst})
}
