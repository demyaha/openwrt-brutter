package cs

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

const (
	PinPrefix       = "brutter_cs_"
	ReconnectPrefix = "brutter_csrc_"
	RejoinPrefix    = "brutter_csrj_"
)

// Server-browser queries from the device must never take the pinned port.
var browserQueries = []byte("TUVW")

// Rules match the device address directly, not through a set: adding a set
// element makes nft load the elements of every set on the router, which takes
// about a second next to a large set such as a proxy whitelist.
func pinRule(table, wan string, client netip.Addr, ep netx.Endpoint, port uint16) string {
	var not []string
	for _, q := range browserQueries {
		not = append(not, fmt.Sprintf("@th,64,40 != 0xffffffff%02x", q))
	}
	return fmt.Sprintf("add rule ip %s pin oifname %q ip saddr %s ip daddr %s udp dport %d %s "+
		"counter masquerade to :%d comment \"pin-%s-%d-%d\"\n",
		table, wan, client, ep.Server, ep.Port, strings.Join(not, " "), port, ep.Server, ep.Port, port)
}

// Pins makes new connections from one device to a saved server leave from
// its chosen port. NAT only sees a connection's first packet, so a rule here
// never moves a running game: it decides the port of the next join.
type Pins struct {
	Client  netip.Addr
	Table   string
	WAN     string
	current map[netx.Endpoint]uint16
	checked time.Time
}

func samePins(a, b map[netx.Endpoint]uint16) bool {
	if a == nil || len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (p *Pins) Apply(pins map[netx.Endpoint]uint16) error {
	if len(pins) == 0 {
		p.Clear()
		return nil
	}
	if samePins(p.current, pins) {
		// The rules are never renewed: check once a minute (about 10 ms) that
		// the table still exists and rebuild it if something removed it.
		if time.Since(p.checked) < time.Minute {
			return nil
		}
		p.checked = time.Now()
		if netx.TableExists(p.Table) {
			return nil
		}
	}
	eps := make([]netx.Endpoint, 0, len(pins))
	for ep := range pins {
		eps = append(eps, ep)
	}
	sort.Slice(eps, func(i, j int) bool {
		return eps[i].Server.Less(eps[j].Server) || eps[i].Server == eps[j].Server && eps[i].Port < eps[j].Port
	})
	var b strings.Builder
	fmt.Fprintf(&b, "add table ip %[1]s\n"+
		// Before fw4 srcnat (100): our port wins for a matching first packet.
		"add chain ip %[1]s pin { type nat hook postrouting priority 99; policy accept; }\n"+
		"flush chain ip %[1]s pin\n", p.Table)
	for _, ep := range eps {
		b.WriteString(pinRule(p.Table, p.WAN, p.Client, ep, pins[ep]))
	}
	if err := netx.Nft(b.String()); err != nil {
		p.current = nil
		return err
	}
	p.checked = time.Now()
	p.current = map[netx.Endpoint]uint16{}
	for k, v := range pins {
		p.current[k] = v
	}
	return nil
}

func (p *Pins) Clear() {
	if p.current == nil || len(p.current) > 0 {
		netx.DeleteTable(p.Table)
	}
	p.current = map[netx.Endpoint]uint16{}
}

var qconnect = regexp.MustCompile(`^\xff\xff\xff\xffqconnect0x[0-9a-fA-F]{8}\x00$`)

// ReconnectPacket returns the IP packet of a CS:GO reconnect request on the
// exact flow, verified enough to be replayed into the stack.
func ReconnectPacket(frame []byte, f netx.Flow) ([]byte, bool) {
	ip, ok := netx.ParseEthernet(frame)
	if !ok {
		return nil, false
	}
	u, err := netx.ParseIPv4UDP(ip, false)
	if err != nil || !u.Complete || u.Src != f.Client || u.Dst != f.Server ||
		u.SPort != f.SPort || u.DPort != f.DPort || !qconnect.Match(u.Payload) {
		return nil, false
	}
	ihl := int(ip[0]&15) * 4
	total := int(binary.BigEndian.Uint16(ip[2:]))
	if netx.Checksum(ip[:ihl]) != 0 {
		return nil, false
	}
	if sum := binary.BigEndian.Uint16(ip[ihl+6:]); sum != 0 {
		pseudo := append(append(append([]byte(nil), ip[12:20]...), 0, 17), ip[ihl+4], ip[ihl+5])
		if netx.Checksum(append(pseudo, ip[ihl:total]...)) != 0 {
			return nil, false
		}
	}
	return append([]byte(nil), ip[:total]...), true
}

type armed struct {
	flow netx.Flow
	port uint16
	stop chan struct{}
	done chan struct{}
}

// Reconnect handles a CS:GO rejoin on the same UDP tuple, which keeps its old
// mapping in conntrack: hold the first qconnect, drop only that exact entry
// and replay the request, so the new connection meets the pin rule.
type Reconnect struct {
	Client   netip.Addr
	Table    string
	LAN, WAN string
	Flows    netx.Table
	mu       sync.Mutex
	armed    *armed
	err      error
}

func (r *Reconnect) batch(f netx.Flow) string {
	prefix := fmt.Sprintf("%x", "\xff\xff\xff\xffqconnect0x")
	return fmt.Sprintf("add table ip %[1]s\n"+
		"add chain ip %[1]s reconnect { type filter hook forward priority -1; policy accept; }\n"+
		"flush chain ip %[1]s reconnect\n"+
		"add rule ip %[1]s reconnect iifname %[2]q oifname %[3]q ip saddr %[4]s ip daddr %[5]s "+
		"udp sport %[6]d udp dport %[7]d udp length 31 @th,64,112 0x%[8]s @th,240,8 0 "+
		"limit rate 1/day burst 1 packets counter drop comment \"cs-reconnect-first\"\n",
		r.Table, r.LAN, r.WAN, r.Client, f.Server, f.SPort, f.DPort, prefix)
}

// Arm watches flow; a rejoin on its tuple will get port.
func (r *Reconnect) Arm(f netx.Flow, port uint16) error {
	r.mu.Lock()
	if a := r.armed; a != nil && a.flow == f && a.port == port {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	r.Disarm()
	sock, err := netx.OpenPacket(r.LAN, true, netx.EthAll, netx.HostPairFilter(f.Client, f.Server, 256))
	if err != nil {
		return err
	}
	if err := netx.Nft(r.batch(f)); err != nil {
		sock.Close()
		return err
	}
	a := &armed{flow: f, port: port, stop: make(chan struct{}), done: make(chan struct{})}
	r.mu.Lock()
	r.armed, r.err = a, nil
	r.mu.Unlock()
	go r.watch(a, sock)
	return nil
}

func (r *Reconnect) watch(a *armed, sock *netx.PacketSocket) {
	defer close(a.done)
	defer sock.Close()
	buf := make([]byte, 512)
	for {
		select {
		case <-a.stop:
			return
		default:
		}
		n, _, err := sock.Read(buf, 300*time.Millisecond)
		if errors.Is(err, netx.ErrNoPacket) {
			continue
		}
		if err != nil {
			r.fail(err)
			return
		}
		if packet, ok := ReconnectPacket(buf[:n], a.flow); ok {
			if err := r.replay(a, packet); err != nil {
				r.fail(err)
			}
			return // At most one replay per armed connection.
		}
	}
}

func (r *Reconnect) fail(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

func (r *Reconnect) intercepted() bool {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(netx.NftList(r.Table)), &doc) != nil {
		return false
	}
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment != "cs-reconnect-first" {
			continue
		}
		for _, e := range item.Rule.Expr {
			var c struct{ Packets int }
			if raw, ok := e["counter"]; ok && json.Unmarshal(raw, &c) == nil && c.Packets > 0 {
				return true
			}
		}
	}
	return false
}

func (r *Reconnect) replay(a *armed, packet []byte) error {
	select {
	case <-a.stop:
		return nil
	default:
	}
	// The capture sees the request before the forward hook drops it.
	for i := 0; i < 20 && !r.intercepted(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !r.intercepted() {
		return errors.New("reconnect request was not intercepted; port kept")
	}
	flows, err := r.Flows.Flows()
	if err != nil {
		return err
	}
	var current *netx.Flow
	for i := range flows {
		if flows[i].Tuple() == a.flow.Tuple() {
			current = &flows[i]
		}
	}
	if current != nil {
		if current.ID != a.flow.ID || current.External != a.flow.External {
			return nil // Replaced already: the join meets the pin rule by itself.
		}
		if netx.Occupied(flows, a.flow.Public, a.flow.Endpoint())[a.port] || netx.LocalUDPPorts()[a.port] {
			return errors.New("pinned port became busy; port kept")
		}
		if err := r.Flows.Delete(*current); err != nil {
			return err
		}
	}
	return netx.SendRaw(r.WAN, packet, a.flow.Server.As4())
}

// Err reports a failed watch since the last Arm.
func (r *Reconnect) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *Reconnect) Disarm() {
	r.mu.Lock()
	a := r.armed
	r.armed = nil
	r.mu.Unlock()
	if a != nil {
		close(a.stop)
		<-a.done
		netx.DeleteTable(r.Table)
	}
}

// Clear also removes a table left by an earlier process.
func (r *Reconnect) Clear() {
	r.Disarm()
	netx.DeleteTable(r.Table)
}

// IsBrowserQuery matches server-browser traffic (A2S and pings), which is
// never the start of a game connection.
func IsBrowserQuery(payload []byte) bool {
	return len(payload) >= 5 && payload[0] == 0xff && payload[1] == 0xff && payload[2] == 0xff &&
		payload[3] == 0xff && strings.IndexByte("TUVWi", payload[4]) >= 0
}

type holding struct {
	flow netx.Flow
	pin  uint16 // the port the pin rule gives
	alt  uint16 // the other pinned port; 0 if the server has none close enough
	stop chan struct{}
	done chan struct{}
}

// Rejoin keeps a quick rejoin on a pinned port.
//
// CS2 opens every connection from a new source port. The previous one keeps
// the pinned port in conntrack for a while, so the pin rule collides and the
// kernel drops the new connection's first packet. The server also ignores a
// new connection from the address it has just closed one on, for about five
// seconds. So the new connection goes to the server's second pinned port, if
// it has one, and otherwise the old entry is dropped so the first port is
// free again. Either way the dropped packet is sent again at once.
type Rejoin struct {
	Client   netip.Addr
	Table    string // nft table for the one-connection rule
	LAN, WAN string
	Flows    netx.Table
	mu       sync.Mutex
	held     *holding
}

// Arm watches for a new connection beside f, the flow on a pinned port.
func (r *Rejoin) Arm(f netx.Flow, pin, alt uint16) error {
	r.mu.Lock()
	if r.held != nil && r.held.flow == f && r.held.pin == pin && r.held.alt == alt {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	r.Disarm()
	sock, err := netx.OpenPacket(r.LAN, true, netx.EthAll, netx.HostPairFilter(f.Client, f.Server, 2048))
	if err != nil {
		return err
	}
	h := &holding{flow: f, pin: pin, alt: alt, stop: make(chan struct{}), done: make(chan struct{})}
	r.mu.Lock()
	r.held = h
	r.mu.Unlock()
	go r.watch(h, sock)
	return nil
}

func (r *Rejoin) watch(h *holding, sock *netx.PacketSocket) {
	defer close(h.done)
	defer sock.Close()
	buf := make([]byte, 2048)
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		n, _, err := sock.Read(buf, 300*time.Millisecond)
		if errors.Is(err, netx.ErrNoPacket) {
			continue
		}
		if err != nil {
			return
		}
		ip, ok := netx.ParseEthernet(buf[:n])
		if !ok {
			continue
		}
		u, err := netx.ParseIPv4UDP(ip, true)
		if err != nil || u.DPort != h.flow.DPort || u.SPort == h.flow.SPort || IsBrowserQuery(u.Payload) {
			continue
		}
		// Only a connection the collision dropped has no conntrack entry.
		time.Sleep(5 * time.Millisecond)
		tuple := netx.Tuple{Client: h.flow.Client, Server: h.flow.Server, SPort: u.SPort, DPort: u.DPort}
		if _, exists, err := r.Flows.Lookup(tuple); err != nil || exists {
			continue
		}
		var packet []byte
		if u.Complete {
			packet = append([]byte(nil), ip[:binary.BigEndian.Uint16(ip[2:])]...)
		}
		r.release(h, u.SPort, packet)
		// Keep watching: the next rejoin may come before the next sync.
	}
}

func (r *Rejoin) free(f netx.Flow, port uint16) bool {
	flows, err := r.Flows.Flows()
	return err == nil && !netx.Occupied(flows, f.Public, f.Endpoint())[port] && !netx.LocalUDPPorts()[port]
}

func (r *Rejoin) release(h *holding, sport uint16, packet []byte) {
	// The other of the two pinned ports, where the server has no fresh closed connection.
	other := h.alt
	if h.flow.External != h.pin {
		other = h.pin
	}
	how := ""
	if other != 0 && other != h.pin && r.free(h.flow, other) {
		batch := fmt.Sprintf("add table ip %[1]s\n"+
			"add chain ip %[1]s rejoin { type nat hook postrouting priority 98; policy accept; }\n"+
			"flush chain ip %[1]s rejoin\n"+
			"add rule ip %[1]s rejoin oifname %[2]q ip saddr %[3]s ip daddr %[4]s udp sport %[5]d udp dport %[6]d counter masquerade to :%[7]d\n",
			r.Table, r.WAN, h.flow.Client, h.flow.Server, sport, h.flow.DPort, other)
		if err := netx.Nft(batch); err == nil {
			how = fmt.Sprintf("second pinned port %d", other)
		}
	}
	if how == "" {
		// Free the first pinned port from whichever of the device's entries holds it.
		flows, err := r.Flows.Flows()
		if err != nil {
			return
		}
		for _, f := range flows {
			if f.Client == h.flow.Client && f.Endpoint() == h.flow.Endpoint() && f.External == h.pin {
				if err := r.Flows.Delete(f); err != nil && !errors.Is(err, netx.ErrChanged) {
					log.Printf("cs %s: rejoin from port %d: %v", r.Client, sport, err)
					return
				}
			}
		}
		how = fmt.Sprintf("pinned port %d, freed", h.pin)
	}
	if packet != nil {
		if err := netx.SendRaw(r.WAN, packet, h.flow.Server.As4()); err != nil {
			how += ", replay failed: " + err.Error()
		}
	}
	log.Printf("cs %s: rejoin from port %d took %s", r.Client, sport, how)
}

func (r *Rejoin) Disarm() {
	r.mu.Lock()
	h := r.held
	r.held = nil
	r.mu.Unlock()
	if h != nil {
		close(h.stop)
		<-h.done
	}
}

// Clear also drops the one-connection rule table.
func (r *Rejoin) Clear() {
	r.Disarm()
	netx.DeleteTable(r.Table)
}
