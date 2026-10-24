package valorant

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

const (
	pollEvery = 2 * time.Second
	// Gameplay runs at tens of packets per second each way; menus and voice do not.
	minRate  = 10.0
	attempts = 3
)

type attempt struct {
	count int
	retry time.Time
	done  bool
}

// Discovery finds a match whose join the capture did not see, for example
// one that started before Brutter. Such a match has no measured current port.
type Discovery struct {
	previous   map[netx.Flow]netx.Flow
	previousAt time.Time
	next       time.Time
	attempted  map[netx.Flow]*attempt
}

func NewDiscovery() *Discovery {
	return &Discovery{previous: map[netx.Flow]netx.Flow{}, attempted: map[netx.Flow]*attempt{}}
}

func ident(f netx.Flow) netx.Flow {
	return netx.Flow{Client: f.Client, Server: f.Server, SPort: f.SPort, DPort: f.DPort, External: f.External}
}

// Active returns the device's busiest game flow on UDP 7000-8000, if any.
func (d *Discovery) Active(flows []netx.Flow, client, public netip.Addr, now time.Time) []netx.Flow {
	current := map[netx.Flow]netx.Flow{}
	var active []netx.Flow
	rates := map[netx.Flow]float64{}
	elapsed := now.Sub(d.previousAt).Seconds()
	for _, f := range flows {
		if f.Client != client || f.Public != public || !gamePort(f.DPort) || !netx.IsPublic(f.Server) {
			continue
		}
		id := ident(f)
		current[id] = f
		old, ok := d.previous[id]
		if !ok || d.previousAt.IsZero() || elapsed <= 0 {
			continue
		}
		out := float64(f.Packets-old.Packets) / elapsed
		in := float64(f.ReplyPackets-old.ReplyPackets) / elapsed
		if f.Packets >= old.Packets && f.ReplyPackets >= old.ReplyPackets && out >= minRate && in >= minRate {
			active = append(active, f)
			rates[id] = out + in
		}
	}
	d.previous, d.previousAt = current, now
	for i := 1; i < len(active); i++ {
		for j := i; j > 0 && rates[ident(active[j])] > rates[ident(active[j-1])]; j-- {
			active[j], active[j-1] = active[j-1], active[j]
		}
	}
	return active
}

// Due says whether a poll should run now.
func (d *Discovery) Due(now time.Time) bool {
	if now.Before(d.next) {
		return false
	}
	d.next = now.Add(pollEvery)
	return true
}

// Try records an attempt on a flow; false while it is backing off or done.
func (d *Discovery) Try(f netx.Flow, now time.Time) bool {
	id := ident(f)
	a := d.attempted[id]
	if a != nil && (a.done || now.Before(a.retry)) {
		return false
	}
	if a == nil {
		if len(d.attempted) > 256 {
			d.attempted = map[netx.Flow]*attempt{}
		}
		a = &attempt{}
		d.attempted[id] = a
	}
	a.count++
	a.retry = now.Add(time.Duration(3*a.count) * time.Second)
	a.done = a.count >= attempts
	return true
}

// Succeeded stops further attempts on a flow.
func (d *Discovery) Succeeded(f netx.Flow) {
	if a := d.attempted[ident(f)]; a != nil {
		a.done = true
	}
}

func (d *Discovery) Reset() {
	d.previous, d.previousAt, d.next = map[netx.Flow]netx.Flow{}, time.Time{}, time.Time{}
	d.attempted = map[netx.Flow]*attempt{}
}

// ObserveOuter reads one outgoing game packet of the flow from the LAN and
// returns only its routing prefix and client id.
func ObserveOuter(lan string, f netx.Flow) ([]byte, uint8, error) {
	sock, err := netx.OpenPacket(lan, true, netx.EthAll, netx.HostPairFilter(f.Client, f.Server, 128))
	if err != nil {
		return nil, 0, err
	}
	defer sock.Close()
	buf := make([]byte, 256)
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		n, _, err := sock.Read(buf, time.Until(end))
		if errors.Is(err, netx.ErrNoPacket) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		ip, ok := netx.ParseEthernet(buf[:n])
		if !ok {
			continue
		}
		u, err := netx.ParseIPv4UDP(ip, true)
		if err != nil || u.SPort != f.SPort || u.DPort != f.DPort || len(u.Payload) < 9 {
			continue
		}
		return append([]byte(nil), u.Payload[:8]...), (u.Payload[8] >> 2) & 7, nil
	}
	return nil, 0, errors.New("no game packet seen")
}

// Verify asks the server for two Challenges from a free port: proof that the
// template belongs to a live Valorant server.
func Verify(public netip.Addr, server netip.AddrPort, template []byte) error {
	h, ok := ParseHeader(template, true, len(template))
	if !ok {
		return errInitial
	}
	s, err := netx.Dial(netip.AddrPortFrom(public, 0), server)
	if err != nil {
		return err
	}
	defer s.Close()
	seq := uint8(128 + rand.IntN(100))
	for i := uint8(0); i < 2; i++ {
		payload, err := Initial(template, seq+i)
		if err != nil {
			return err
		}
		sent, err := s.Send(payload)
		if err != nil {
			return err
		}
		matched := false
		for end := sent.Add(replyTimeout); time.Now().Before(end); {
			data, _, err := s.Receive(end)
			if err != nil {
				break
			}
			if IsChallenge(data, seq+i, h.CID) {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("no matching Valorant Challenge")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}
