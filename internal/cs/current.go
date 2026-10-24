package cs

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

const currentSamples = 5

// Current is the device's own port measured on its live mapping.
type Current struct {
	Port    uint16    `json:"port"`
	RTT     *float64  `json:"rtt_ms"`
	Samples []float64 `json:"samples_ms,omitempty"`
	Spread  float64   `json:"spread_ms,omitempty"`
	Stable  bool      `json:"stable"`
	Error   string    `json:"error,omitempty"`
	At      int64     `json:"measured_at,omitempty"`
}

// nextHop returns nil on PPP links, or the gateway's MAC on Ethernet ones.
func nextHop(wan string, f netx.Flow) (net.HardwareAddr, error) {
	kind, err := os.ReadFile("/sys/class/net/" + wan + "/type")
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(string(kind)) {
	case "512": // PPP
		return nil, nil
	case "1": // Ethernet
	default:
		return nil, errors.New("WAN must be an Ethernet or PPP interface")
	}
	route, err := exec.Command("ip", "-4", "route", "get", f.Server.String(), "from", f.Public.String()).Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(route))
	gateway := f.Server.String()
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" && fields[i+1] != wan {
			return nil, errors.New("server route no longer uses the configured WAN")
		}
		if fields[i] == "via" {
			gateway = fields[i+1]
		}
	}
	neigh, err := exec.Command("ip", "-4", "neigh", "show", "to", gateway, "dev", wan).Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(neigh), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" && !strings.Contains(line, "FAILED") && !strings.Contains(line, "INCOMPLETE") {
				if mac, err := net.ParseMAC(f[i+1]); err == nil && mac[0]&1 == 0 {
					return mac, nil
				}
			}
		}
	}
	// Never guess a MAC: an active game normally has a resolved neighbor.
	return nil, errors.New("WAN gateway neighbor is unresolved")
}

type currentProbe struct {
	table  netx.Table
	flow   netx.Flow
	mac    net.HardwareAddr
	rx, tx *netx.PacketSocket
	sent   [][]byte
	buf    []byte
	public func() (bool, error)
}

func (c *currentProbe) unchanged() error {
	if ok, err := c.public(); err != nil || !ok {
		return errors.New("WAN changed during the measurement")
	}
	flows, err := c.table.Flows()
	if err != nil {
		return err
	}
	for _, f := range flows {
		if f.Tuple() == c.flow.Tuple() && f.ID == c.flow.ID && f.External == c.flow.External {
			return nil
		}
	}
	return errors.New("the game connection changed")
}

func (c *currentProbe) send(payload []byte) (time.Time, error) {
	if err := c.unchanged(); err != nil {
		return time.Time{}, err
	}
	packet := netx.Datagram(c.flow.Public, c.flow.Server, c.flow.External, c.flow.DPort, payload, uint16(rand.IntN(65536)))
	c.sent = append(c.sent, packet)
	at := time.Now()
	return at, c.tx.Send(packet, c.mac)
}

// event returns the next A2S reply on the mapping. A query from the device
// itself on the same port makes the timing ambiguous.
func (c *currentProbe) event(wait time.Duration) ([]byte, time.Time, error) {
	end := time.Now().Add(wait)
	for time.Now().Before(end) {
		n, at, err := c.rx.Read(c.buf, time.Until(end))
		if errors.Is(err, netx.ErrNoPacket) {
			break
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		u, err := netx.ParseIPv4UDP(c.buf[:n], false)
		if err != nil || len(u.Payload) < 5 {
			continue
		}
		f := c.flow
		if u.Src == f.Public && u.Dst == f.Server && u.SPort == f.External && u.DPort == f.DPort {
			ours := false
			for _, p := range c.sent {
				if bytes.Equal(p, c.buf[:n]) {
					ours = true
				}
			}
			if !ours && bytes.IndexByte([]byte("TUV"), u.Payload[4]) >= 0 {
				return nil, time.Time{}, errors.New("the device queried this server too; measurement is ambiguous")
			}
			continue
		}
		if u.Src == f.Server && u.Dst == f.Public && u.SPort == f.DPort && u.DPort == f.External &&
			(u.Payload[4] == 'I' || u.Payload[4] == 'A') {
			return append([]byte(nil), u.Payload...), at, nil
		}
	}
	return nil, time.Time{}, nil
}

func (c *currentProbe) quiet(wait time.Duration) error {
	if p, _, err := c.event(wait); err != nil || p != nil {
		if err == nil {
			err = errors.New("unexpected A2S reply; measurement is ambiguous")
		}
		return err
	}
	return nil
}

func (c *currentProbe) query(challenge []byte) (float64, []byte, error) {
	sent, err := c.send(append(append([]byte(nil), Query...), challenge...))
	if err != nil {
		return 0, nil, err
	}
	reply, at, err := c.event(a2sWait)
	if err != nil || reply == nil {
		return 0, nil, orTimeout(err)
	}
	if reply[4] == 'A' {
		if len(reply) != 9 {
			return 0, nil, errors.New("invalid A2S challenge")
		}
		challenge = reply[5:9]
		if err := c.quiet(50 * time.Millisecond); err != nil {
			return 0, nil, err
		}
		if sent, err = c.send(append(append([]byte(nil), Query...), challenge...)); err != nil {
			return 0, nil, err
		}
		if reply, at, err = c.event(a2sWait); err != nil || reply == nil {
			return 0, nil, orTimeout(err)
		}
	}
	info, err := ParseInfo(reply)
	if err != nil {
		return 0, nil, err
	}
	if info.AppID != AppID {
		return 0, nil, errors.New("the server is not a CS server")
	}
	if err := c.quiet(100 * time.Millisecond); err != nil {
		return 0, nil, err
	}
	return float64(at.Sub(sent).Microseconds()) / 1000, challenge, nil
}

func orTimeout(err error) error {
	if err != nil {
		return err
	}
	return errors.New("current port A2S timeout")
}

// MeasureCurrent sends A2S as if from the device's live mapping, straight onto
// the WAN, without opening a socket or touching NAT. The game server answers
// on its tick, so each sample carries up to one tick of delay; the minimum of
// several samples is the path's round trip.
func MeasureCurrent(table netx.Table, wan string, flow netx.Flow, sameWAN func() (bool, error)) Current {
	result := Current{Port: flow.External, At: time.Now().Unix()}
	fail := func(err error) Current {
		result.Error = err.Error()
		return result
	}
	if !flow.Assured {
		return fail(errors.New("the game connection is not established"))
	}
	mac, err := nextHop(wan, flow)
	if err != nil {
		return fail(err)
	}
	rx, err := netx.OpenPacket(wan, false, netx.EthAll, netx.ServerQueryFilter(flow.Server))
	if err != nil {
		return fail(err)
	}
	defer rx.Close()
	tx, err := netx.OpenPacket(wan, false, 0, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Close()
	c := &currentProbe{table: table, flow: flow, mac: mac, rx: rx, tx: tx, buf: make([]byte, 4096), public: sameWAN}
	if err := c.quiet(300 * time.Millisecond); err != nil {
		return fail(err)
	}
	var challenge []byte
	for i := 0; i < currentSamples; i++ {
		rtt, next, err := c.query(challenge)
		if err != nil {
			return fail(err)
		}
		challenge = next
		result.Samples = append(result.Samples, rtt)
		time.Sleep(150 * time.Millisecond)
	}
	if err := c.unchanged(); err != nil {
		return fail(err)
	}
	low, high := result.Samples[0], result.Samples[0]
	for _, s := range result.Samples {
		low, high = min(low, s), max(high, s)
	}
	result.RTT = &low
	result.Spread = float64(int((high-low)*100)) / 100
	result.Stable = high-low <= 3
	return result
}

func (c Current) String() string {
	if c.RTT == nil {
		return "unmeasured: " + c.Error
	}
	return fmt.Sprintf("%.1f ms", *c.RTT)
}
