package cs

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

var (
	clock  = time.Unix(1792320000, 0)
	now    = func() time.Time { return clock }
	served = netx.Endpoint{Server: netip.MustParseAddr("203.0.113.7"), Port: 27015}
)

func rtt(v float64) *float64 { return &v }

func probes(pairs ...float64) []Probe {
	var out []Probe
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Probe{Port: uint16(pairs[i]), RTT: rtt(pairs[i+1])})
	}
	return out
}

func TestVersionOneFilesKeepTheirServersAndPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	os.WriteFile(path, []byte(`{"version": 1, "servers": [
	 {"public": "198.51.100.1", "server": "203.0.113.7", "dport": 27015, "last_played": 1792319062.4,
	  "ports": [{"port": 22665, "rtt_ms": 19.22, "measured_at": 1}, {"port": 61334, "rtt_ms": 19.63, "measured_at": 1}]},
	 {"public": "198.51.100.2", "server": "203.0.113.7", "dport": 27015, "last_played": 1792000000,
	  "ports": [{"port": 40000, "rtt_ms": 10, "measured_at": 1}]},
	 {"public": "198.51.100.1", "server": "10.0.0.1", "dport": 27015, "last_played": 1792319062.4, "ports": []}
	]}`), 0o600)
	s := OpenStore(path, now)
	entries := s.Entries()
	if len(entries) != 1 || s.Warning != "" {
		t.Fatalf("entries %+v warning %q", entries, s.Warning)
	}
	v := entries[0]
	if v.Best.Port != 22665 || v.Effective(false).Port != 22665 || v.Effective(true).Port != 22665 {
		t.Fatalf("migrated %+v", v)
	}
}

// A server on the device's own port gets the fastest port from its first
// scan, live or a manual check from the list.
func TestAServerWithoutAPinGetsTheFastestPort(t *testing.T) {
	s := OpenStore(filepath.Join(t.TempDir(), "s.json"), now)
	v, ok := s.Record(served, probes(40000, 20, 41000, 25), &Reading{27005, 21}, 27005, true)
	if !ok || v.Effective(false) == nil || v.Effective(false).Port != 40000 {
		t.Fatalf("live scan: auto %+v", v.Effective(false))
	}
	other := served
	other.Port++
	v, ok = s.Record(other, probes(42000, 30, 43000, 28), nil, 0, false)
	if !ok || v.Effective(false) == nil || v.Effective(false).Port != 43000 {
		t.Fatalf("manual check: auto %+v", v.Effective(false))
	}
}

func TestRescanOnThePinnedPortKeepsItWithoutAClearWinner(t *testing.T) {
	s := OpenStore(filepath.Join(t.TempDir(), "s.json"), now)
	s.Record(served, probes(40000, 20), &Reading{27005, 30}, 27005, true)
	// Live again on 40000: a slightly better port must not unpin it.
	v, _ := s.Record(served, probes(41000, 19.5), &Reading{40000, 20.5}, 0, true)
	if v.Auto == nil || v.Auto.Port != 40000 || v.Original != 27005 {
		t.Fatalf("pin lost: %+v", v)
	}
}

func TestOfflineCheckMovesThePinOnlyForAClearGain(t *testing.T) {
	s := OpenStore(filepath.Join(t.TempDir(), "s.json"), now)
	s.Record(served, probes(40000, 20), &Reading{27005, 30}, 27005, true)
	v, _ := s.Get(served)
	if got := v.Preferred(); len(got) < 2 || got[len(got)-1] != 27005 {
		t.Fatalf("preferred %v", got)
	}
	// After a reboot the device's own port is as good: the pin stays.
	v, _ = s.Record(served, probes(40000, 20, 27005, 20.5), nil, 0, false)
	if v.Auto == nil || v.Auto.Port != 40000 || v.Best.Port != 40000 || v.LastPlayed == 0 {
		t.Fatalf("pin %+v best %+v", v.Auto, v.Best)
	}
	// A port 1 ms faster than the pin does not move it; 3 ms does.
	if v, _ = s.Record(served, probes(40000, 20, 44000, 19), nil, 0, false); v.Auto.Port != 40000 {
		t.Fatalf("moved for 1 ms: %+v", v.Auto)
	}
	if v, _ = s.Record(served, probes(40000, 20, 44000, 17), nil, 0, false); v.Auto.Port != 44000 {
		t.Fatalf("kept despite 3 ms: %+v", v.Auto)
	}
}

func TestFailedScanOfANewServerSavesNothing(t *testing.T) {
	s := OpenStore(filepath.Join(t.TempDir(), "s.json"), now)
	if _, ok := s.Record(served, []Probe{{Port: 40000}}, nil, 27005, true); ok || s.Has(served) {
		t.Fatal("empty scan saved")
	}
}

func TestStoreSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	s := OpenStore(path, now)
	s.Record(served, probes(40000, 20), &Reading{27005, 30}, 27005, true)
	again := OpenStore(path, now)
	v, ok := again.Get(served)
	if !ok || v.Auto == nil || v.Auto.Port != 40000 || v.Reference.Port != 27005 {
		t.Fatalf("reloaded %+v", v)
	}
	again.Remove(served)
	if OpenStore(path, now).Has(served) {
		t.Fatal("removed server came back")
	}
}

func TestSecondPinnedPortIsCloseToTheFirst(t *testing.T) {
	s := OpenStore(filepath.Join(t.TempDir(), "s.json"), now)
	v, _ := s.Record(served, probes(40000, 18.7, 41000, 18.8, 42000, 25), &Reading{27005, 30}, 27005, true)
	if a := v.Alternate(false); a == nil || a.Port != 41000 {
		t.Fatalf("alternate %+v", a)
	}
	v, _ = s.Record(served, probes(40000, 18.7, 42000, 25), &Reading{27005, 30}, 27005, true)
	if a := v.Alternate(false); a != nil {
		t.Fatalf("a port 6 ms slower must not be pinned: %+v", a)
	}
	// The device's own port is close now: the pin and its alternate stay.
	v, _ = s.Record(served, probes(40000, 20, 41000, 20.5), &Reading{27005, 21}, 27005, true)
	if a := v.Alternate(false); a == nil || a.Port != 41000 {
		t.Fatalf("alternate after a close own port %+v", a)
	}
}
