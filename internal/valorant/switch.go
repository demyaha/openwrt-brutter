package valorant

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

// SwitchPrefix names the per-device tables; leftovers are removed at start.
const SwitchPrefix = "brutter_sw_"

// One live switch at a time on the whole router.
var switching sync.Mutex

// Switcher moves one device's live mapping to another port. It writes only
// its own nft table and the game's exact conntrack entry.
type Switcher struct {
	Table   netx.Table
	WAN     string
	Name    string // nft table
	Tracker *Tracker
	Wait    func(time.Duration) // test hook; sleeps by default
}

// Result of a switch attempt.
type Result struct {
	Kept   bool
	After  *float64 // restart round trip on the new port
	Reason string
}

func (s *Switcher) sleep(d time.Duration) {
	if s.Wait != nil {
		s.Wait(d)
		return
	}
	time.Sleep(d)
}

func (s *Switcher) find(t netx.Tuple) (netx.Flow, []netx.Flow, error) {
	flows, err := s.Table.Flows()
	if err != nil {
		return netx.Flow{}, nil, err
	}
	for _, f := range flows {
		if f.Tuple() == t {
			return f, flows, nil
		}
	}
	return netx.Flow{}, flows, errGone
}

var errGone = errors.New("the game connection is gone")

func (s *Switcher) rule(f netx.Flow, port uint16) string {
	return fmt.Sprintf("add table ip %[1]s\n"+
		"add chain ip %[1]s sw { type nat hook postrouting priority 98; policy accept; }\n"+
		"flush chain ip %[1]s sw\n"+
		"add rule ip %[1]s sw oifname %[2]q ip saddr %[3]s ip daddr %[4]s udp sport %[5]d udp dport %[6]d counter masquerade to :%[7]d\n",
		s.Name, s.WAN, f.Client, f.Server, f.SPort, f.DPort, port)
}

// moveTo sends the next packet of the flow through a rule for port and waits
// until the server answers on it.
func (s *Switcher) moveTo(f netx.Flow, port uint16) (netx.Flow, error) {
	if err := netx.Nft(s.rule(f, port)); err != nil {
		return netx.Flow{}, err
	}
	if err := s.Table.Delete(f); err != nil && !errors.Is(err, netx.ErrChanged) {
		return netx.Flow{}, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if g, _, err := s.find(f.Tuple()); err == nil && g.External == port && g.ReplyPackets > 0 {
			return g, nil
		}
		s.sleep(40 * time.Millisecond)
	}
	return netx.Flow{}, errors.New("the game did not resume within five seconds")
}

// exact reads the entry from the kernel: the shared dump can be older than a
// progress check's wait and would show frozen counters.
func (s *Switcher) exact(t netx.Tuple) (netx.Flow, error) {
	f, ok, err := s.Table.Lookup(t)
	if err != nil {
		return netx.Flow{}, err
	}
	if !ok {
		return netx.Flow{}, errGone
	}
	return f, nil
}

// progressing waits up to wait for packets to move both ways on the exact
// entry; a game loading its map sends only now and then.
func (s *Switcher) progressing(f netx.Flow, wait time.Duration) (netx.Flow, error) {
	const step = 100 * time.Millisecond
	before, err := s.exact(f.Tuple())
	if err != nil {
		return netx.Flow{}, err
	}
	for waited := time.Duration(0); waited < wait; waited += step {
		s.sleep(step)
		after, err := s.exact(f.Tuple())
		if err != nil {
			return netx.Flow{}, err
		}
		if after.ID != before.ID || after.External != f.External {
			return netx.Flow{}, errors.New("the game connection changed")
		}
		if after.Packets > before.Packets && after.ReplyPackets > before.ReplyPackets {
			return after, nil
		}
	}
	return netx.Flow{}, errors.New("game traffic stopped")
}

// Apply moves flow to port. keep decides on the restart round trip; any
// failure puts the previous port back.
func (s *Switcher) Apply(flow netx.Flow, port uint16, cancelled func() bool, keep func(*float64) bool) (res Result, err error) {
	switching.Lock()
	defer switching.Unlock()
	// Linux marks UDP ASSURED about two seconds after the first reply.
	deadline := time.Now().Add(5 * time.Second)
	var current netx.Flow
	var flows []netx.Flow
	for {
		if cancelled() {
			return Result{}, ErrCancelled
		}
		current, flows, err = s.find(flow.Tuple())
		if err != nil {
			return Result{}, err
		}
		if current.Assured {
			break
		}
		if time.Now().After(deadline) {
			return Result{}, errors.New("the game connection is not established yet")
		}
		s.sleep(200 * time.Millisecond)
	}
	if current.External != flow.External || current.Public != flow.Public {
		return Result{}, errors.New("the game port mapping has changed")
	}
	if netx.Occupied(flows, current.Public, current.Endpoint())[port] || netx.LocalUDPPorts()[port] {
		return Result{Reason: "port_occupied"}, nil
	}
	if _, err := s.progressing(current, 2*time.Second); err != nil {
		return Result{}, fmt.Errorf("before the switch: %w", err)
	}
	original := current.External
	switched := false
	defer func() {
		if switched {
			if rerr := s.restore(flow.Tuple(), original); rerr != nil {
				err = fmt.Errorf("%v; previous port not restored: %v", err, rerr)
			}
		} else {
			netx.DeleteTable(s.Name)
		}
	}()
	switched = true
	at := time.Now()
	moved, err := s.moveTo(current, port)
	if err != nil {
		return Result{Reason: "verification_failed"}, err
	}
	key := Key{Server: flow.Server, SPort: flow.SPort, DPort: flow.DPort}
	var sample *Sample
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); s.sleep(100 * time.Millisecond) {
		if cancelled() {
			return Result{}, ErrCancelled
		}
		if sample = s.Tracker.Latest(key, at); sample != nil {
			break
		}
	}
	if sample == nil {
		return Result{Reason: "verification_failed"}, errors.New("the server did not acknowledge the new port")
	}
	if _, err := s.progressing(moved, 2*time.Second); err != nil {
		return Result{Reason: "verification_failed"}, fmt.Errorf("after the switch: %w", err)
	}
	if !keep(sample.RTT) {
		return Result{After: sample.RTT, Reason: "verification_failed"}, nil
	}
	switched = false // keep: the entry holds the new port without the rule
	return Result{Kept: true, After: sample.RTT}, nil
}

// restore puts the device back on its previous port, or on whatever NAT picks
// when that port is gone.
func (s *Switcher) restore(t netx.Tuple, original uint16) error {
	defer netx.DeleteTable(s.Name)
	current, flows, err := s.find(t)
	if errors.Is(err, errGone) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.External == original {
		return nil
	}
	if netx.Occupied(flows, current.Public, current.Endpoint())[original] {
		return s.Table.Delete(current)
	}
	_, err = s.moveTo(current, original)
	return err
}

// CleanupSwitches removes tables left by a process that died mid-switch.
func CleanupSwitches() {
	for _, name := range netx.NftTables() {
		if strings.HasPrefix(name, SwitchPrefix) {
			netx.DeleteTable(name)
		}
	}
}
