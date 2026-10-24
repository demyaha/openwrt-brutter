package netx

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Socket is a connected UDP socket whose replies carry kernel arrival times,
// so a busy router does not add scheduling delay to a round trip.
type Socket struct {
	conn *net.UDPConn
	Port uint16
	buf  []byte
	oob  []byte
}

// Dial binds local (port 0 picks a free one) and connects to remote.
func Dial(local, remote netip.AddrPort) (*Socket, error) {
	dialer := net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(local),
		Control: func(_, _ string, raw syscall.RawConn) error {
			var inner error
			if err := raw.Control(func(fd uintptr) { inner = enableTimestamps(int(fd)) }); err != nil {
				return err
			}
			return inner
		},
	}
	c, err := dialer.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		return nil, err
	}
	conn := c.(*net.UDPConn)
	return &Socket{
		conn: conn,
		Port: uint16(conn.LocalAddr().(*net.UDPAddr).Port),
		buf:  make([]byte, 4096),
		oob:  make([]byte, 128),
	}, nil
}

// Send writes payload and returns the wall-clock send time.
func (s *Socket) Send(payload []byte) (time.Time, error) {
	sent := time.Now()
	_, err := s.conn.Write(payload)
	return sent, err
}

// Receive waits until deadline for one datagram and its arrival time.
// The returned slice is valid until the next Receive.
func (s *Socket) Receive(deadline time.Time) ([]byte, time.Time, error) {
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nil, time.Time{}, err
	}
	n, oobn, _, _, err := s.conn.ReadMsgUDP(s.buf, s.oob)
	if err != nil {
		return nil, time.Time{}, err
	}
	return s.buf[:n], arrival(s.oob[:oobn]), nil
}

func (s *Socket) Close() error { return s.conn.Close() }

// IsTimeout reports a read deadline expiry.
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// LocalUDPPorts lists UDP ports bound by the router itself; NAT must never
// map a device onto one of them.
func LocalUDPPorts() map[uint16]bool {
	ports := map[uint16]bool{}
	for _, name := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		file, err := os.Open(name)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				continue
			}
			i := strings.LastIndexByte(fields[1], ':')
			if p, err := strconv.ParseUint(fields[1][i+1:], 16, 16); err == nil {
				ports[uint16(p)] = true
			}
		}
		file.Close()
	}
	return ports
}

// WANAddress is the first IPv4 address of an up interface.
func WANAddress(name string) (netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, err
	}
	if iface.Flags&net.FlagUp == 0 {
		return netip.Addr{}, errors.New("WAN device is down")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && n.IP.To4() != nil {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, errors.New("WAN has no IPv4 address")
}
