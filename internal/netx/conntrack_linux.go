package netx

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ti-mo/conntrack"
	"golang.org/x/sys/unix"
)

// Conntrack is a Table over netlink, with dumps shared for a short moment so
// several workers polling in the same second cost one kernel dump.
type Conntrack struct {
	mu     sync.Mutex
	conn   *conntrack.Conn
	cached []Flow
	at     time.Time
}

const shareDump = 200 * time.Millisecond

func (c *Conntrack) dial() (*conntrack.Conn, error) {
	if c.conn == nil {
		conn, err := conntrack.Dial(nil)
		if err != nil {
			return nil, err
		}
		c.conn = conn
	}
	return c.conn, nil
}

func (c *Conntrack) Flows() ([]Flow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil && time.Since(c.at) < shareDump {
		return c.cached, nil
	}
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	raw, err := conn.Dump(nil)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return nil, err
	}
	flows := make([]Flow, 0, len(raw)/2)
	for _, f := range raw {
		o, r := f.TupleOrig, f.TupleReply
		if o.Proto.Protocol != 17 || !o.IP.SourceAddress.Is4() {
			continue
		}
		flows = append(flows, Flow{
			ID:           f.ID,
			Client:       o.IP.SourceAddress,
			Server:       o.IP.DestinationAddress,
			Public:       r.IP.DestinationAddress,
			SPort:        o.Proto.SourcePort,
			DPort:        o.Proto.DestinationPort,
			External:     r.Proto.DestinationPort,
			Packets:      f.CountersOrig.Packets,
			ReplyPackets: f.CountersReply.Packets,
			Assured:      f.Status.Assured(),
		})
	}
	c.cached, c.at = flows, time.Now()
	return flows, nil
}

// Delete removes exactly the observed entry: same tuple and same conntrack ID.
func (c *Conntrack) Delete(f Flow) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, err := c.dial()
	if err != nil {
		return err
	}
	query := conntrack.NewFlow(17, 0, f.Client, f.Server, f.SPort, f.DPort, 0, 0)
	current, err := conn.Get(query)
	if err != nil {
		return err
	}
	if f.ID != 0 && current.ID != f.ID {
		return ErrChanged
	}
	c.cached = nil
	return conn.Delete(query)
}

// DeleteLocal removes the router's own probe flow from public:port to an endpoint.
func (c *Conntrack) DeleteLocal(public netip.Addr, port uint16, ep Endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, err := c.dial()
	if err != nil {
		return
	}
	c.cached = nil
	_ = conn.Delete(conntrack.NewFlow(17, 0, public, ep.Server, port, ep.Port, 0, 0))
}

// Lookup finds the entry of one exact tuple, bypassing the shared dump.
func (c *Conntrack) Lookup(t Tuple) (Flow, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, err := c.dial()
	if err != nil {
		return Flow{}, false, err
	}
	f, err := conn.Get(conntrack.NewFlow(17, 0, t.Client, t.Server, t.SPort, t.DPort, 0, 0))
	if err != nil {
		if errors.Is(err, unix.ENOENT) || strings.Contains(err.Error(), "no such file") {
			return Flow{}, false, nil
		}
		return Flow{}, false, err
	}
	o, r := f.TupleOrig, f.TupleReply
	return Flow{ID: f.ID, Client: o.IP.SourceAddress, Server: o.IP.DestinationAddress,
		Public: r.IP.DestinationAddress, SPort: o.Proto.SourcePort, DPort: o.Proto.DestinationPort,
		External: r.Proto.DestinationPort, Packets: f.CountersOrig.Packets,
		ReplyPackets: f.CountersReply.Packets, Assured: f.Status.Assured()}, true, nil
}
