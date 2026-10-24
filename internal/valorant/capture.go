package valorant

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/bpf"

	"github.com/demyaha/brutter/internal/netx"
)

// snapLen keeps headers only: no game or authentication payload is copied.
const snapLen = 256

// HandshakeFilter passes Ethernet/IPv4/UDP frames whose payload carries the
// v3/4 handshake bits, to or from UDP 7000-8000. Device addresses are checked
// in Go, so one capture serves every selected device.
func HandshakeFilter() []bpf.Instruction {
	const drop, accept = 255, 254 // placeholders resolved below
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                             // 0 ethertype
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: drop},  // 1
		bpf.LoadAbsolute{Off: 23, Size: 1},                             // 2 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: drop},      // 3
		bpf.LoadAbsolute{Off: 20, Size: 2},                             // 4 fragment bits
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x3fff, SkipTrue: drop}, // 5
		bpf.LoadMemShift{Off: 14},                                      // 6 x = IP header length
		// Outgoing: destination port 7000-8000, header at payload byte 8.
		bpf.LoadIndirect{Off: 16, Size: 2},                               // 7 dport
		bpf.JumpIf{Cond: bpf.JumpLessThan, Val: PortMin, SkipTrue: 8},    // 8 -> 17
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: PortMax, SkipTrue: 7}, // 9 -> 17
		bpf.LoadIndirect{Off: 30, Size: 1},                               // 10
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x20, SkipFalse: 5},       // 11 -> 17
		bpf.LoadIndirect{Off: 31, Size: 1},                               // 12
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipFalse: 3},            // 13 -> 17
		bpf.LoadIndirect{Off: 32, Size: 1},                               // 14
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x7f},                   // 15
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipTrue: accept},        // 16
		// Incoming: source port 7000-8000, header at payload byte 4.
		bpf.LoadIndirect{Off: 14, Size: 2},                                  // 17 sport
		bpf.JumpIf{Cond: bpf.JumpLessThan, Val: PortMin, SkipTrue: drop},    // 18
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: PortMax, SkipTrue: drop}, // 19
		bpf.LoadIndirect{Off: 26, Size: 1},                                  // 20
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x20, SkipFalse: drop},       // 21
		bpf.LoadIndirect{Off: 27, Size: 1},                                  // 22
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipFalse: drop},            // 23
		bpf.LoadIndirect{Off: 28, Size: 1},                                  // 24
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x7f},                      // 25
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipTrue: accept},           // 26
		bpf.RetConstant{Val: 0},                                             // 27 drop
		bpf.RetConstant{Val: snapLen},                                       // 28 accept
	}
	dropAt, acceptAt := len(prog)-2, len(prog)-1
	for i, ins := range prog {
		if j, ok := ins.(bpf.JumpIf); ok {
			fix := func(skip uint8) uint8 {
				switch skip {
				case drop:
					return uint8(dropAt - i - 1)
				case accept:
					return uint8(acceptAt - i - 1)
				}
				return skip
			}
			j.SkipTrue, j.SkipFalse = fix(j.SkipTrue), fix(j.SkipFalse)
			prog[i] = j
		}
	}
	return prog
}

// Capture reads handshake packets on the LAN bridge and hands each one to
// the tracker of the device it belongs to.
type Capture struct {
	mu       sync.Mutex
	sock     *netx.PacketSocket
	trackers map[netip.Addr]func(Packet, time.Time)
	stop     chan struct{}
	done     chan struct{}
	Err      error
	Received int
}

// OpenCapture starts the shared capture on the LAN interface.
func OpenCapture(lan string) (*Capture, error) {
	sock, err := netx.OpenPacket(lan, true, netx.EthAll, HandshakeFilter())
	if err != nil {
		return nil, err
	}
	c := &Capture{sock: sock, trackers: map[netip.Addr]func(Packet, time.Time){},
		stop: make(chan struct{}), done: make(chan struct{})}
	go c.run()
	return c, nil
}

// Attach routes a device's packets to fn; nil detaches it.
func (c *Capture) Attach(client netip.Addr, fn func(Packet, time.Time)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fn == nil {
		delete(c.trackers, client)
	} else {
		c.trackers[client] = fn
	}
}

func (c *Capture) run() {
	defer close(c.done)
	buf := make([]byte, 2048)
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		n, ts, err := c.sock.Read(buf, 500*time.Millisecond)
		if errors.Is(err, netx.ErrNoPacket) {
			continue
		}
		if err != nil {
			c.mu.Lock()
			c.Err = err
			c.mu.Unlock()
			return
		}
		ip, ok := netx.ParseEthernet(buf[:n])
		if !ok {
			continue
		}
		p, ok := Decode(ip)
		if !ok {
			continue
		}
		p.Payload = append([]byte(nil), p.Payload...)
		c.mu.Lock()
		c.Received++
		fn := c.trackers[p.Client]
		c.mu.Unlock()
		if fn != nil {
			fn(p, ts)
		}
	}
}

// Failed reports a capture that stopped on an error.
func (c *Capture) Failed() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Err
}

func (c *Capture) Close() {
	close(c.stop)
	<-c.done
	c.sock.Close()
}
