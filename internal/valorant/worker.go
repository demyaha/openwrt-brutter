package valorant

import (
	"errors"
	"log"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/demyaha/brutter/internal/activity"
	"github.com/demyaha/brutter/internal/config"
	"github.com/demyaha/brutter/internal/netx"
	"github.com/demyaha/brutter/internal/settings"
)

const (
	minGainMS      = 2.0
	afterTolerance = 10.0             // one noisy restart sample against a seven-sample median
	joinedSamples  = 6                // as many as a scan finalist gets
	restartWindow  = 15 * time.Second // the game re-handshakes after our switch; that is not a join
	livenessEvery  = 2 * time.Second
	sessionIdle    = 10 * time.Second
	game           = settings.Valorant
)

// Table is what the worker needs from conntrack.
type Table interface {
	netx.Table
	DeleteLocal(netip.Addr, uint16, netx.Endpoint)
}

// Env is everything a device's worker shares with the rest of Brutter.
type Env struct {
	Client   netip.Addr
	WAN, LAN string
	Table    Table
	Settings *settings.Store
	Board    *activity.Board
	Capture  *Capture
}

// Status is what the dashboard shows for Valorant on one device.
type Status struct {
	Phase           string         `json:"phase"`
	SessionActive   bool           `json:"session_active"`
	Server          string         `json:"server,omitempty"`
	DPort           uint16         `json:"dport,omitempty"`
	OriginalPort    uint16         `json:"original_port,omitempty"`
	CurrentPort     uint16         `json:"current_port,omitempty"`
	Baseline        *float64       `json:"baseline_ms"`
	BaselineSamples []Sample       `json:"baseline_samples,omitempty"`
	BusyJoin        bool           `json:"busy_join,omitempty"`
	Joined          *float64       `json:"joined_ms"` // the join port, probed once the switch freed it
	Source          string         `json:"detection_source,omitempty"`
	DetectedAt      int64          `json:"detected_at,omitempty"`
	ScanCompleted   int            `json:"scan_completed"`
	ScanTotal       int            `json:"scan_total"`
	Probes          []Probe        `json:"probes"`
	Selected        *Probe         `json:"selected"`
	After           *float64       `json:"after_ms"`
	Gain            *float64       `json:"gain_ms"`
	Forced          bool           `json:"forced"`
	Reason          string         `json:"reason,omitempty"`
	Error           string         `json:"error,omitempty"`
	OtherGame       string         `json:"other_game,omitempty"`
	RescanAvailable bool           `json:"rescan_available"`
	RescanPending   bool           `json:"rescan_pending"`
	Handshakes      map[string]int `json:"handshake_stats"`
	CaptureError    string         `json:"capture_error,omitempty"`
	UpdatedAt       int64          `json:"updated_at"`
}

type match struct {
	event     *Event
	flow      netx.Flow
	active    bool
	progress  time.Time
	reference *float64 // current port's latest round trip
	best      *Probe
	applied   bool
	busyJoin  bool      // the join timed the server's load, not the port
	switched  time.Time // our last move of this match
}

var finalPhases = map[string]bool{"applied": true, "unchanged": true, "restored": true}

type Worker struct {
	env        Env
	tracker    *Tracker
	discovery  *Discovery
	mu         sync.Mutex
	status     Status
	inbox      []*Event
	signal     chan struct{}
	match      *match
	pending    *Event
	suspended  string
	forceSeen  bool
	generation uint64
	attached   bool
	rescan     atomic.Bool
	stop       chan struct{}
	done       chan struct{}
	nextLive   time.Time
	lastPub    time.Time
}

func NewWorker(env Env) *Worker {
	w := &Worker{env: env, tracker: NewTracker(), discovery: NewDiscovery(),
		signal: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		forceSeen: env.Settings.Force(), generation: env.Settings.Generation()}
	w.status = Status{Phase: "waiting", Probes: []Probe{}}
	return w
}

// Status returns a copy for the dashboard.
func (w *Worker) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.status
	s.Handshakes = w.tracker.Stats()
	s.RescanPending = w.rescan.Load()
	if c := w.env.Capture; c != nil {
		if err := c.Failed(); err != nil {
			s.CaptureError = err.Error()
		}
	}
	return s
}

func (w *Worker) update(fn func(*Status)) {
	w.mu.Lock()
	fn(&w.status)
	m := w.match
	w.status.SessionActive = m != nil && m.active
	w.status.RescanAvailable = w.status.SessionActive && finalPhases[w.status.Phase] &&
		w.env.Settings.Active(game)
	w.status.UpdatedAt = time.Now().Unix()
	w.mu.Unlock()
	w.lastPub = time.Now()
}

// RequestRescan queues a new scan of the live match.
func (w *Worker) RequestRescan() error {
	s := w.Status()
	if !s.RescanAvailable || s.RescanPending {
		return errors.New("Valorant rescan is unavailable")
	}
	w.rescan.Store(true)
	w.wake()
	return nil
}

func (w *Worker) wake() {
	select {
	case w.signal <- struct{}{}:
	default:
	}
}

// feed runs on the capture goroutine.
func (w *Worker) feed(p Packet, ts time.Time) {
	if e := w.tracker.Feed(p, ts); e != nil {
		w.offer(e)
	}
}

func (w *Worker) offer(e *Event) {
	w.mu.Lock()
	w.inbox = append(w.inbox, e)
	if len(w.inbox) > 8 {
		w.inbox = w.inbox[1:]
	}
	w.mu.Unlock()
	w.wake()
}

func (w *Worker) newest() *Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	var latest *Event
	for _, e := range w.inbox {
		if latest == nil || e.CapturedAt.After(latest.CapturedAt) {
			latest = e
		}
	}
	return latest
}

func (w *Worker) take(timeout time.Duration) *Event {
	select {
	case <-w.signal:
	case <-time.After(timeout):
	case <-w.stop:
	}
	for _, e := range w.tracker.Due(time.Now()) {
		w.offer(&e)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var latest *Event
	for _, e := range w.inbox {
		if latest == nil || e.CapturedAt.After(latest.CapturedAt) {
			latest = e
		}
	}
	w.inbox = nil
	return latest
}

func (w *Worker) stopped() bool {
	select {
	case <-w.stop:
		return true
	default:
		return false
	}
}

// cancelled tells a running scan or switch to give way.
func (w *Worker) cancelled() bool {
	if w.stopped() || w.env.Settings.Generation() != w.generation || !w.env.Settings.Active(game) {
		return true
	}
	if w.env.Capture != nil && w.env.Capture.Failed() != nil {
		return true
	}
	m := w.match
	if n := w.newest(); m != nil && n != nil && n.CapturedAt.After(m.event.CapturedAt) && n.Key != m.event.Key {
		return true
	}
	return false
}

func (w *Worker) public() (netip.Addr, error) { return netx.WANAddress(w.env.WAN) }

func (w *Worker) flow(k Key) (netx.Flow, error) {
	flows, err := w.env.Table.Flows()
	if err != nil {
		return netx.Flow{}, err
	}
	for _, f := range flows {
		if f.Client == w.env.Client && f.Server == k.Server && f.SPort == k.SPort && f.DPort == k.DPort {
			return f, nil
		}
	}
	return netx.Flow{}, errGone
}

// endMatch forgets the live match but keeps its results on screen.
func (w *Worker) endMatch(reason string) {
	if w.match != nil {
		w.match.active = false
		w.env.Board.Release(w.env.Client, game)
	}
	w.match = nil
	w.update(func(s *Status) {
		if reason != "" || s.Phase == "connecting" || s.Phase == "scanning" || s.Phase == "switching" {
			s.Phase, s.Reason = "waiting", reason
		}
	})
}

func (w *Worker) liveness() {
	m := w.match
	if m == nil || time.Now().Before(w.nextLive) {
		return
	}
	w.nextLive = time.Now().Add(livenessEvery)
	f, err := w.flow(m.event.Key)
	if err != nil {
		w.endMatch("connection_closed")
		return
	}
	if f.Packets != m.flow.Packets || f.ReplyPackets != m.flow.ReplyPackets {
		m.progress = time.Now()
	}
	m.flow = f
	w.update(func(s *Status) { s.CurrentPort = f.External })
	if time.Since(m.progress) >= sessionIdle {
		w.endMatch("connection_closed")
		return
	}
	w.env.Board.Claim(w.env.Client, game)
}

func (w *Worker) start(e *Event) error {
	w.endMatch("")
	w.update(func(s *Status) {
		*s = Status{Phase: "connecting", Server: e.Server.String(), DPort: e.DPort,
			Baseline: e.Baseline, BaselineSamples: e.Samples, Source: e.Source,
			DetectedAt: time.Now().Unix(), Probes: []Probe{}}
	})
	log.Printf("valorant %s: %s join %s:%d", w.env.Client, e.Source, e.Server, e.DPort)
	var f netx.Flow
	var err error
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if w.cancelled() {
			return ErrCancelled
		}
		if f, err = w.flow(e.Key); err == nil && f.Packets > 0 && f.ReplyPackets > 0 {
			break
		}
		if time.Now().After(end) {
			return errGone
		}
	}
	if public, err := w.public(); err != nil || public != f.Public {
		return errors.New("the WAN address has changed")
	}
	if !w.env.Board.Claim(w.env.Client, game) {
		w.pending = e
		return nil
	}
	w.match = &match{event: e, flow: f, active: true, progress: time.Now(), reference: e.Baseline}
	w.update(func(s *Status) { s.OriginalPort, s.CurrentPort = f.External, f.External })
	return w.scan(w.match)
}

func (w *Worker) scan(m *match) error {
	count := w.env.Settings.Count(game)
	w.update(func(s *Status) {
		s.Phase, s.ScanCompleted, s.ScanTotal, s.Probes, s.Selected = "scanning", 0, count, []Probe{}, nil
		s.After, s.Gain, s.Forced, s.Reason, s.Error = nil, nil, false, "", ""
	})
	server := netip.AddrPortFrom(m.flow.Server, m.flow.DPort)
	prober, err := NewProber(m.flow.Public, server, m.event.Template, w.cancelled)
	if err != nil {
		return err
	}
	defer prober.Close(w.env.Table)
	flows, err := w.env.Table.Flows()
	if err != nil {
		return err
	}
	occupied := netx.Occupied(flows, m.flow.Public, m.flow.Endpoint())
	for p := range netx.LocalUDPPorts() {
		occupied[p] = true
	}
	occupied[m.flow.External] = true
	if err := prober.Allocate(count, occupied); err != nil {
		return err
	}
	last := time.Time{}
	probes, best, err := prober.Measure(func(done, total int) {
		// A scan can outlast the device's claim: keep it, or the other game wakes up.
		w.env.Board.Claim(w.env.Client, game)
		if done == total || time.Since(last) >= 250*time.Millisecond {
			last = time.Now()
			w.update(func(s *Status) { s.ScanCompleted, s.ScanTotal = done, total })
		}
	})
	if err != nil {
		return err
	}
	f, err := w.flow(m.event.Key)
	if err != nil {
		return err
	}
	if f.External != m.flow.External {
		return errors.New("the game port mapping changed during the scan")
	}
	m.best = best
	// A join slower than every scanned port cannot stand for the current one.
	if slow := slowest(probes); !m.applied && m.reference != nil && slow != nil && *m.reference > *slow {
		m.reference, m.busyJoin = nil, true
	}
	w.update(func(s *Status) { s.Probes, s.Selected, s.BusyJoin = probes, best, m.busyJoin })
	// The winner is still bound by its probe socket and mapped by its probe
	// entry; the switch needs both gone.
	prober.Close(w.env.Table)
	return w.decide(m, w.env.Settings.Force())
}

func (w *Worker) decide(m *match, force bool) error {
	best := m.best
	if best == nil {
		w.update(func(s *Status) { s.Phase, s.Reason = "unchanged", "no_replies" })
		return nil
	}
	var gain *float64
	if m.reference != nil {
		g := math.Round((*m.reference-*best.RTT)*100) / 100
		gain = &g
	}
	confirmed := gain != nil && *gain >= minGainMS
	// Without a usable join timing (a busy server, or a match Brutter picked up
	// late) the fastest port is the best guess; the join port is probed once
	// the switch frees it, and the device goes back if it was faster.
	blind := m.reference == nil
	forced := !confirmed && !blind
	if !force && forced {
		w.update(func(s *Status) { s.Phase, s.Reason, s.Gain = "unchanged", "no_clear_gain", gain })
		return nil
	}
	w.update(func(s *Status) { s.Phase, s.Gain, s.Forced = "switching", gain, forced })
	reference := m.reference
	keep := func(after *float64) bool {
		// The restart completed. Its timing cannot judge a forced move, nor one
		// made while the server is still busy with the join.
		if after == nil || force || blind {
			return true
		}
		if *after > *best.RTT+afterTolerance {
			return false
		}
		return !confirmed || reference == nil || *after <= *reference
	}
	sw := &Switcher{Table: w.env.Table, WAN: w.env.WAN, Name: SwitchPrefix + config.Key(w.env.Client), Tracker: w.tracker}
	res, err := sw.Apply(m.flow, best.Port, w.cancelled, keep)
	if errors.Is(err, ErrCancelled) {
		return err
	}
	if err != nil {
		w.update(func(s *Status) {
			s.Phase, s.Reason, s.Error = "restored", "verification_failed", err.Error()
			if res.Reason == "" { // failed before anything moved
				s.Phase, s.Reason = "unchanged", "not_switched"
			}
		})
		log.Printf("valorant %s: switch to %d failed: %v", w.env.Client, best.Port, err)
		return nil
	}
	w.nextLive = time.Time{}
	if res.Kept {
		joined, first := m.flow.External, !m.applied
		m.flow.External = best.Port
		m.applied, m.switched = true, time.Now()
		// A restart reading from a still busy server would make the next
		// scan move again.
		m.reference = best.RTT
		if res.After != nil && *res.After <= *best.RTT+afterTolerance {
			m.reference = res.After
		}
		w.update(func(s *Status) {
			s.Phase, s.CurrentPort, s.After, s.Forced, s.Reason = "applied", best.Port, res.After, forced, ""
		})
		log.Printf("valorant %s: moved to port %d", w.env.Client, best.Port)
		if first {
			if rtt := w.measureJoined(m, joined, best); rtt != nil && *rtt+minGainMS <= *best.RTT {
				w.moveBack(m, sw, joined, *rtt)
			}
		}
		return nil
	}
	w.update(func(s *Status) {
		s.After, s.Reason = res.After, res.Reason
		s.Phase = "restored"
		if res.Reason == "port_occupied" {
			s.Phase = "unchanged"
		}
	})
	if res.After != nil {
		log.Printf("valorant %s: port %d answered in %.1f ms, previous port kept", w.env.Client, best.Port, *res.After)
	}
	return nil
}

// measureJoined times the port the device joined with. The join handshake
// cannot stand for it while the server is busy, but the switch has freed the
// port, so it is probed exactly like the scanned ones.
func (w *Worker) measureJoined(m *match, port uint16, best *Probe) *float64 {
	if port == 0 || port == best.Port {
		return nil
	}
	flows, err := w.env.Table.Flows()
	if err != nil || netx.Occupied(flows, m.flow.Public, m.flow.Endpoint())[port] || netx.LocalUDPPorts()[port] {
		return nil
	}
	prober, err := NewProber(m.flow.Public, netip.AddrPortFrom(m.flow.Server, m.flow.DPort), m.event.Template, w.cancelled)
	if err != nil {
		return nil
	}
	defer prober.Close(w.env.Table)
	probe, err := prober.MeasureOne(port, joinedSamples)
	if err != nil || probe.RTT == nil {
		log.Printf("valorant %s: join port %d not measured: %v", w.env.Client, port, err)
		return nil
	}
	w.update(func(s *Status) {
		s.Joined = probe.RTT
		if g := math.Round((*probe.RTT-*best.RTT)*100) / 100; s.Gain == nil && g > 0 {
			s.Gain = &g
		}
	})
	log.Printf("valorant %s: join port %d measured %.1f ms", w.env.Client, port, *probe.RTT)
	return probe.RTT
}

// moveBack returns the device to its join port, which the probe found faster
// than the scan's winner.
func (w *Worker) moveBack(m *match, sw *Switcher, port uint16, rtt float64) {
	res, err := sw.Apply(m.flow, port, w.cancelled, func(*float64) bool { return true })
	if err != nil || !res.Kept {
		log.Printf("valorant %s: return to join port %d failed: %v", w.env.Client, port, err)
		return
	}
	m.flow.External, m.reference, m.switched = port, &rtt, time.Now()
	w.update(func(s *Status) { s.Phase, s.CurrentPort, s.Reason, s.Gain = "unchanged", port, "join_port_faster", nil })
	log.Printf("valorant %s: join port %d was faster; moved back", w.env.Client, port)
}

func (w *Worker) guarded(fn func() error) {
	err := fn()
	switch {
	case err == nil:
	case errors.Is(err, ErrCancelled):
		w.endMatch("cancelled")
	case errors.Is(err, errGone):
		w.endMatch("connection_closed")
	default:
		w.update(func(s *Status) { s.Phase, s.Error = "error", err.Error() })
		log.Printf("valorant %s: %v", w.env.Client, err)
	}
}

func (w *Worker) reset() {
	w.endMatch("")
	w.pending = nil
	w.rescan.Store(false)
	w.tracker = NewTracker()
	w.discovery.Reset()
	w.mu.Lock()
	w.inbox = nil
	w.mu.Unlock()
	w.attach(w.env.Settings.Active(game))
	w.update(func(s *Status) { *s = Status{Phase: "waiting", Probes: []Probe{}} })
}

func (w *Worker) attach(on bool) {
	if w.env.Capture == nil || on == w.attached {
		return
	}
	if on {
		w.env.Capture.Attach(w.env.Client, w.feed)
	} else {
		w.env.Capture.Attach(w.env.Client, nil)
	}
	w.attached = on
}

func (w *Worker) tick() {
	if g := w.env.Settings.Generation(); g != w.generation {
		w.generation = g
		w.reset()
	}
	if !w.env.Settings.Active(game) {
		w.attach(false)
		w.endMatch("")
		w.pending = nil
		w.rescan.Store(false)
		w.update(func(s *Status) { s.Phase = "disabled" })
		select {
		case <-w.stop:
		case <-w.signal:
		case <-time.After(time.Second):
		}
		return
	}
	w.attach(true)
	if w.Status().Phase == "disabled" {
		w.update(func(s *Status) { s.Phase = "waiting" })
	}
	event := w.take(500 * time.Millisecond)
	if m := w.match; event != nil && m != nil && event.Key == m.event.Key && time.Since(m.switched) < restartWindow {
		event = nil // the game confirming the port we just gave it
	}
	if other := w.env.Board.Other(w.env.Client, game); other != "" {
		if event != nil {
			w.pending = event
		}
		if w.suspended == "" {
			w.suspended = w.Status().Phase
		}
		w.update(func(s *Status) { s.Phase, s.OtherGame = "suspended", other })
		return
	}
	if w.suspended != "" {
		previous := w.suspended
		w.suspended = ""
		w.update(func(s *Status) { s.Phase, s.OtherGame = previous, "" })
	}
	if event == nil && w.pending != nil {
		event, w.pending = w.pending, nil
	}
	w.liveness()
	if event != nil {
		w.guarded(func() error { return w.start(event) })
	} else if w.match == nil && w.discovery.Due(time.Now()) {
		w.guarded(w.recover)
	}
	if w.rescan.Swap(false) && w.match != nil && w.match.active {
		m := w.match
		w.guarded(func() error { return w.scan(m) })
	}
	force := w.env.Settings.Force()
	if m := w.match; force && !w.forceSeen && m != nil && m.active && m.best != nil && !m.applied {
		if p := w.Status().Phase; p == "unchanged" || p == "restored" {
			w.guarded(func() error { return w.decide(m, true) })
		}
	}
	w.forceSeen = force
	if time.Since(w.lastPub) >= 5*time.Second {
		w.update(func(*Status) {})
	}
}

// recover looks for a match whose join the capture missed.
func (w *Worker) recover() error {
	public, err := w.public()
	if err != nil {
		return nil
	}
	flows, err := w.env.Table.Flows()
	if err != nil {
		return nil
	}
	for _, f := range w.discovery.Active(flows, w.env.Client, public, time.Now()) {
		if !w.discovery.Try(f, time.Now()) {
			continue
		}
		key := Key{f.Server, f.SPort, f.DPort}
		template := w.tracker.Known(key)
		if template == nil {
			outer, cid, err := ObserveOuter(w.env.LAN, f)
			if err != nil {
				continue
			}
			if template, err = RecoveryInitial(outer, cid); err != nil {
				continue
			}
		}
		if Verify(public, netip.AddrPortFrom(f.Server, f.DPort), template) != nil {
			continue
		}
		w.discovery.Succeeded(f)
		return w.start(&Event{Key: key, Template: template, CapturedAt: time.Now(), Source: "recovered"})
	}
	return nil
}

// Run serves one device until Stop.
func (w *Worker) Run() {
	defer close(w.done)
	w.update(func(*Status) {})
	for !w.stopped() {
		w.tick()
	}
	w.attach(false)
	w.env.Board.Release(w.env.Client, game)
	w.update(func(s *Status) { s.Phase = "stopped" })
}

func (w *Worker) Stop() {
	close(w.stop)
	<-w.done
}
