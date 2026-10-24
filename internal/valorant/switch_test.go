package valorant

import (
	"net/netip"
	"testing"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

// liveTable serves a frozen dump, like the shared one, while exact lookups
// see the game's counters grow.
type liveTable struct {
	flow         netx.Flow
	every, calls int // counters grow on every n-th lookup; 0 means each one
}

func (l *liveTable) Flows() ([]netx.Flow, error) { return []netx.Flow{l.flow}, nil }
func (l *liveTable) Delete(netx.Flow) error      { return nil }
func (l *liveTable) Lookup(netx.Tuple) (netx.Flow, bool, error) {
	l.calls++
	if l.every == 0 || l.calls%l.every == 0 {
		l.flow.Packets += 10
		l.flow.ReplyPackets += 10
	}
	return l.flow, true, nil
}

func TestProgressWaitsForALoadingGame(t *testing.T) {
	flow := netx.Flow{ID: 7, SPort: 53551, DPort: 7121, External: 53551, Packets: 100, ReplyPackets: 100}
	// A packet each way every 700 ms, as while the map loads.
	sw := &Switcher{Table: &liveTable{flow: flow, every: 7}, Wait: func(time.Duration) {}}
	if _, err := sw.progressing(flow, 2*time.Second); err != nil {
		t.Fatalf("sparse traffic reported as stopped: %v", err)
	}
	idle := &Switcher{Table: &liveTable{flow: flow, every: 1000}, Wait: func(time.Duration) {}}
	if _, err := idle.progressing(flow, 2*time.Second); err == nil {
		t.Fatal("silent connection reported as live")
	}
}

func TestSlowestIgnoresSilentPorts(t *testing.T) {
	a, b := 48.8, 65.2
	if s := slowest([]Probe{{RTT: &a}, {}, {RTT: &b}}); s == nil || *s != b {
		t.Fatalf("slowest %v", s)
	}
	if slowest([]Probe{{}}) != nil {
		t.Fatal("no replies has no slowest port")
	}
}

func TestProgressIgnoresTheSharedDump(t *testing.T) {
	flow := netx.Flow{ID: 7, Client: netip.MustParseAddr("192.168.1.100"), Server: netip.MustParseAddr("203.0.113.10"),
		Public: netip.MustParseAddr("198.51.100.7"), SPort: 53551, DPort: 7121, External: 53551,
		Packets: 100, ReplyPackets: 100, Assured: true}
	sw := &Switcher{Table: &liveTable{flow: flow}, Wait: func(time.Duration) {}}
	if _, err := sw.progressing(flow, 100*time.Millisecond); err != nil {
		t.Fatalf("live traffic reported as stopped: %v", err)
	}
}
