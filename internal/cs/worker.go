package cs

import (
	"errors"
	"log"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/demyaha/brutter/internal/activity"
	"github.com/demyaha/brutter/internal/netx"
	"github.com/demyaha/brutter/internal/settings"
)

const (
	game         = settings.CS
	activePPS    = 5.0              // a match sends tens of packets per second each way
	targetIdle   = 15 * time.Second // without traffic, the device has left the server
	stalePinned  = 5 * time.Second  // idle mapping holding the pin after a rejoin elsewhere
	staleOther   = 70 * time.Second // longer than a server's client timeout: that join is over
	notCSFor     = 10 * time.Minute
	freshPackets = 4               // both ways, on first sight
	playingIdle  = 5 * time.Second // a pinned entry without traffic for this long is not a game
	busyCheck    = 2 * time.Second
	scanRounds   = 3
	poll         = time.Second // a pass is about 10 ms of CPU on a Cortex-A53
	valorantLow  = 7000
	valorantHigh = 8000
)

var ignoredPorts = map[uint16]bool{53: true, 123: true, 443: true, 3478: true}

var (
	errStopping    = errors.New("stopping")
	errInterrupted = errors.New("scan interrupted")
)

// Table is what the worker needs from conntrack.
type Table interface {
	netx.Table
	DeleteLocal(netip.Addr, uint16, netx.Endpoint)
}

// Env is everything a device's worker shares with the rest of Brutter.
type Env struct {
	Client    netip.Addr
	WAN, LAN  string
	Table     Table
	Settings  *settings.Store
	Board     *activity.Board
	Store     *Store
	Pins      *Pins
	Reconnect *Reconnect
	Rejoin    *Rejoin
	// Others are ports pinned by the other devices; a port is never pinned twice.
	Others func() map[uint16]bool
	// Boot asks for every saved server to be checked once: the router restarted.
	Boot bool
}

type Progress struct {
	Done  int `json:"done"`
	Total int `json:"total"`
}

// ServerView is one saved server as the dashboard lists it.
type ServerView struct {
	Server     string    `json:"server"`
	DPort      uint16    `json:"dport"`
	Name       string    `json:"name,omitempty"`
	Port       uint16    `json:"port,omitempty"` // pinned port; absent keeps NAT's choice
	RTT        *float64  `json:"rtt_ms"`
	State      string    `json:"state"`
	InGame     bool      `json:"in_game"`
	Best       *Reading  `json:"best"`
	Reference  *Reading  `json:"reference"`
	CheckedAt  *float64  `json:"checked_at"`
	LastPlayed float64   `json:"last_played"`
	Progress   *Progress `json:"progress,omitempty"`
}

// Status is what the dashboard shows for CS on one device.
type Status struct {
	Phase           string       `json:"phase"`
	Server          string       `json:"server,omitempty"`
	DPort           uint16       `json:"dport,omitempty"`
	Name            string       `json:"name,omitempty"`
	CurrentPort     uint16       `json:"current_port,omitempty"`
	PinnedPort      uint16       `json:"pinned_port,omitempty"`
	Best            *Reading     `json:"best"`
	Auto            *Reading     `json:"auto"`
	Alternate       *Reading     `json:"alternate"`
	Reference       *Reading     `json:"reference"`
	Gain            *float64     `json:"gain_ms"`
	Forced          bool         `json:"forced"`
	Probes          []Probe      `json:"probes"`
	Current         *Current     `json:"current"`
	ScanCompleted   int          `json:"scan_completed"`
	ScanTotal       int          `json:"scan_total"`
	Error           string       `json:"error,omitempty"`
	OtherGame       string       `json:"other_game,omitempty"`
	RescanAvailable bool         `json:"rescan_available"`
	Servers         []ServerView `json:"servers"`
	Warning         string       `json:"warning,omitempty"`
	UpdatedAt       int64        `json:"updated_at"`
}

type seen struct {
	netx.Flow
	progress time.Time
	at       time.Time
	rate     float64
}

type ident struct {
	server       netip.Addr
	sport, dport uint16
	external     uint16
}

func identOf(f netx.Flow) ident { return ident{f.Server, f.SPort, f.DPort, f.External} }

type request struct {
	kind string
	ep   netx.Endpoint
}

type lastScan struct {
	ep      netx.Endpoint
	probes  []Probe
	current *Current
}

type Worker struct {
	env  Env
	mu   sync.Mutex
	stat Status
	reqs []request
	chk  *struct {
		ep netx.Endpoint
		Progress
	}
	armed map[netx.Endpoint]uint16
	held  map[netx.Endpoint]bool // pinned port carrying this device's game right now
	// second pinned port per server, for quick rejoins
	alternates map[netx.Endpoint]uint16
	silent     map[netx.Endpoint]bool // no port got an answer on the last check

	wake chan struct{}
	stop chan struct{}
	done chan struct{}

	flows      map[ident]*seen
	primed     bool // flows holds a previous pass: an entry missing from it is new
	target     *seen
	public     netip.Addr
	known      map[netx.Endpoint]bool
	names      map[netx.Endpoint]string
	asked      map[netx.Endpoint]time.Time // A2S name lookups for saved servers
	notCS      map[netx.Endpoint]time.Time
	ignored    map[ident]bool
	scanned    map[netx.Endpoint]bool
	last       *lastScan
	queue      []netx.Endpoint
	paused     bool
	suspended  bool
	generation uint64
	identified bool
}

func NewWorker(env Env) *Worker {
	w := &Worker{env: env, armed: map[netx.Endpoint]uint16{}, held: map[netx.Endpoint]bool{},
		alternates: map[netx.Endpoint]uint16{}, silent: map[netx.Endpoint]bool{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
		flows: map[ident]*seen{}, known: map[netx.Endpoint]bool{}, notCS: map[netx.Endpoint]time.Time{},
		names: map[netx.Endpoint]string{}, asked: map[netx.Endpoint]time.Time{},
		ignored: map[ident]bool{}, scanned: map[netx.Endpoint]bool{},
		generation: env.Settings.Generation()}
	w.stat = Status{Phase: "waiting", Probes: []Probe{}}
	if env.Boot {
		// RAM is empty after a router reboot: check every saved server once.
		for _, v := range env.Store.Entries() {
			w.queue = append(w.queue, v.Endpoint())
		}
	}
	return w
}

func (w *Worker) publish(fn func(*Status)) {
	w.mu.Lock()
	fn(&w.stat)
	w.stat.UpdatedAt = time.Now().Unix()
	w.mu.Unlock()
}

func (w *Worker) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Armed returns the ports this device has pinned.
func (w *Worker) Armed() map[uint16]bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[uint16]bool{}
	for _, p := range w.armed {
		out[p] = true
	}
	for _, p := range w.alternates {
		out[p] = true
	}
	return out
}

// Request queues a panel action: rescan the live server, refresh or remove a saved one.
func (w *Worker) Request(kind string, ep netx.Endpoint) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.reqs) >= 32 {
		return errors.New("too many pending actions")
	}
	switch kind {
	case "rescan":
		if !w.stat.RescanAvailable {
			return errors.New("no live CS server to scan")
		}
	case "refresh", "remove":
		if !w.env.Store.Has(ep) {
			return errors.New("unknown saved server")
		}
		if kind == "refresh" && w.chk != nil && w.chk.ep == ep {
			return errors.New("server check already running")
		}
	default:
		return errors.New("unknown action")
	}
	for _, r := range w.reqs {
		if r == (request{kind, ep}) {
			return errors.New("already queued")
		}
	}
	w.reqs = append(w.reqs, request{kind, ep})
	w.signal()
	return nil
}

// Status returns a copy for the dashboard, with the saved server list.
func (w *Worker) Status() Status {
	w.mu.Lock()
	s := w.stat
	s.Probes = append([]Probe(nil), s.Probes...)
	w.mu.Unlock()
	s.Servers = w.servers()
	s.Warning = w.env.Store.Warning
	return s
}

func (w *Worker) servers() []ServerView {
	force := w.env.Settings.Force()
	w.mu.Lock()
	target := w.stat.Server
	targetPort, current := w.stat.DPort, w.stat.CurrentPort
	queued := map[netx.Endpoint]bool{}
	removing := map[netx.Endpoint]bool{}
	for _, r := range w.reqs {
		queued[r.ep] = queued[r.ep] || r.kind == "refresh"
		removing[r.ep] = removing[r.ep] || r.kind == "remove"
	}
	for _, ep := range w.queue {
		queued[ep] = true
	}
	var chk *struct {
		ep netx.Endpoint
		Progress
	}
	if w.chk != nil {
		c := *w.chk
		chk = &c
	}
	armed := map[netx.Endpoint]uint16{}
	for k, v := range w.armed {
		armed[k] = v
	}
	held := map[netx.Endpoint]bool{}
	for k, v := range w.held {
		held[k] = v
	}
	silent := map[netx.Endpoint]bool{}
	for k, v := range w.silent {
		silent[k] = v
	}
	live := w.stat.Phase != "waiting" && w.stat.Phase != "disabled" && w.stat.Phase != "suspended"
	// Turned off, every pin is lifted on purpose; that is not a busy port.
	off := w.stat.Phase == "disabled"
	w.mu.Unlock()
	entries := w.env.Store.Entries()
	out := make([]ServerView, 0, len(entries))
	for _, v := range entries {
		ep := v.Endpoint()
		view := ServerView{Server: v.Server, DPort: v.DPort, Name: v.Name, Best: v.Best, Reference: v.Reference,
			CheckedAt: v.CheckedAt, LastPlayed: v.LastPlayed}
		alt := v.Alternate(force)
		if pin := v.Effective(force); pin != nil {
			view.Port, view.RTT = pin.Port, &pin.RTT
		}
		view.InGame = live && target == v.Server && targetPort == v.DPort
		switch {
		case removing[ep]:
			view.State = "removing"
		case chk != nil && chk.ep == ep:
			view.State = "checking"
			p := chk.Progress
			view.Progress = &p
		case view.InGame && view.Port != 0 && current != view.Port && (alt == nil || current != alt.Port):
			view.State = "ready"
		case view.InGame, held[ep]:
			view.State = "in_game"
		case queued[ep]:
			view.State = "queued"
		case silent[ep]:
			view.State = "silent"
		case view.Port == 0:
			view.State = "default"
		case off:
			view.State = "off"
		case armed[ep] != 0:
			view.State = "pinned"
		default:
			view.State = "blocked"
		}
		out = append(out, view)
	}
	return out
}

// check makes a running scan give way to Reset, Off, the other game or removal.
func (w *Worker) check() error {
	select {
	case <-w.stop:
		return errStopping
	default:
	}
	if w.env.Settings.Generation() != w.generation || !w.env.Settings.Active(game) ||
		w.env.Board.Other(w.env.Client, game) != "" {
		return errInterrupted
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.chk != nil {
		for _, r := range w.reqs {
			if r.kind == "remove" && r.ep == w.chk.ep {
				return errInterrupted
			}
		}
	}
	return nil
}

func (w *Worker) observe(flows []netx.Flow, now time.Time) {
	current := map[ident]*seen{}
	for _, f := range flows {
		if f.Client != w.env.Client || f.Public != w.public || ignoredPorts[f.DPort] || !netx.IsPublic(f.Server) {
			continue
		}
		id := identOf(f)
		s := &seen{Flow: f, progress: now, at: now}
		if old, ok := w.flows[id]; ok {
			s.progress = old.progress
			if f.Packets != old.Packets || f.ReplyPackets != old.ReplyPackets {
				s.progress = now
			}
			if elapsed := now.Sub(old.at).Seconds(); elapsed > 0 && f.Packets >= old.Packets && f.ReplyPackets >= old.ReplyPackets {
				s.rate = math.Min(float64(f.Packets-old.Packets), float64(f.ReplyPackets-old.ReplyPackets)) / elapsed
			}
		}
		current[id] = s
	}
	for id := range w.ignored {
		if current[id] == nil {
			delete(w.ignored, id)
		}
	}
	w.identified = false
	var chosen *seen
	for id, s := range current {
		_, old := w.flows[id]
		// A rejoin to a known server is a new entry with no rate yet; a browser
		// query to it is only a packet or two each way.
		fresh := w.primed && !old && s.Packets >= freshPackets && s.ReplyPackets >= freshPackets &&
			(w.env.Store.Has(s.Endpoint()) || w.known[s.Endpoint()])
		if (s.rate < activePPS && !fresh) || w.ignored[id] || (chosen != nil && chosen.rate >= s.rate && !fresh) {
			continue
		}
		if w.isCS(s.Flow, now) {
			chosen = s
		}
	}
	if chosen != nil && !w.env.Board.Claim(w.env.Client, game) {
		chosen = nil
	}
	if chosen == nil && w.target != nil {
		if s := current[identOf(w.target.Flow)]; s != nil && now.Sub(s.progress) < targetIdle {
			chosen = s
			w.env.Board.Claim(w.env.Client, game)
		}
	}
	w.flows, w.primed = current, true
	if chosen == nil {
		if w.target != nil {
			w.env.Board.Release(w.env.Client, game)
		}
		// The game is over: its scan leaves the dashboard with it.
		w.target, w.last = nil, nil
		return
	}
	if w.target == nil || w.target.Endpoint() != chosen.Endpoint() {
		w.publish(func(s *Status) { s.Current, s.Error = nil, "" })
		log.Printf("cs %s: playing on %s:%d from port %d", w.env.Client, chosen.Server, chosen.DPort, chosen.External)
	}
	w.target = chosen
	w.env.Store.Touch(chosen.Endpoint())
}

func (w *Worker) isCS(f netx.Flow, now time.Time) bool {
	ep := f.Endpoint()
	if w.env.Store.Has(ep) || w.known[ep] {
		return true
	}
	if (f.DPort >= valorantLow && f.DPort <= valorantHigh) || now.Before(w.notCS[ep]) || w.identified {
		return false
	}
	w.identified = true // at most one A2S check per pass
	busy := map[uint16]bool{}
	if flows, err := w.env.Table.Flows(); err == nil {
		busy = netx.Occupied(flows, w.public, ep)
	}
	for p := range netx.LocalUDPPorts() {
		busy[p] = true
	}
	found := false
	if probes, err := ProbePorts(w.env.Table, w.env.Table.DeleteLocal, w.public, ep, RandomPorts(1, busy), 1,
		func() error { return nil }, func() {}); err == nil && len(probes) == 1 && len(probes[0].Samples) == 1 {
		found = true
		if probes[0].Info != nil {
			w.names[ep] = probes[0].Info.Name
		}
	}
	if found {
		w.known[ep] = true
	} else {
		if len(w.notCS) > 256 {
			w.notCS = map[netx.Endpoint]time.Time{}
		}
		w.notCS[ep] = now.Add(notCSFor)
	}
	return found
}

func (w *Worker) syncPins(flows []netx.Flow) {
	force := w.env.Settings.Force()
	others := w.env.Others()
	local := netx.LocalUDPPorts()
	wanted := map[netx.Endpoint]uint16{}
	alternates := map[netx.Endpoint]uint16{}
	held := map[netx.Endpoint]bool{}
	var holder *netx.Flow
	for _, v := range w.env.Store.Entries() {
		pin := v.Effective(force)
		if pin == nil || local[pin.Port] || others[pin.Port] {
			continue
		}
		ep := v.Endpoint()
		if alt := v.Alternate(force); alt != nil && !local[alt.Port] && !others[alt.Port] {
			alternates[ep] = alt.Port
		}
		ownPin := false
		for _, f := range flows {
			if f.Client != w.env.Client || f.Endpoint() != ep || (f.External != pin.Port && f.External != alternates[ep]) {
				continue
			}
			ownPin = ownPin || f.External == pin.Port
			// An entry lingers in conntrack after the game leaves; only traffic means playing.
			if s := w.flows[identOf(f)]; s != nil && time.Since(s.progress) < playingIdle {
				held[ep] = true
			}
			isTarget := w.target != nil && identOf(w.target.Flow) == identOf(f)
			if holder == nil || isTarget {
				copied := f
				holder = &copied
			}
		}
		// Another device's mapping holds the port: a rule would only collide.
		// Our own stays armed for a rejoin, which Rejoin makes room for.
		if netx.Occupied(flows, w.public, ep)[pin.Port] && !ownPin {
			continue
		}
		wanted[ep] = pin.Port
	}
	if err := w.env.Pins.Apply(wanted); err != nil {
		w.publish(func(s *Status) { s.Error = err.Error() })
		wanted = map[netx.Endpoint]uint16{}
	}
	w.mu.Lock()
	w.armed, w.held, w.alternates = wanted, held, alternates
	w.mu.Unlock()
	if holder != nil && wanted[holder.Endpoint()] != 0 {
		ep := holder.Endpoint()
		if err := w.env.Rejoin.Arm(*holder, wanted[ep], alternates[ep]); err != nil {
			w.publish(func(s *Status) { s.Error = err.Error() })
		}
	} else {
		w.env.Rejoin.Disarm()
	}
}

// releaseStale frees mappings that would keep the next join off its pin.
func (w *Worker) releaseStale(now time.Time) {
	force := w.env.Settings.Force()
	for _, s := range w.flows {
		v, ok := w.env.Store.Get(s.Endpoint())
		pin := v.Effective(force)
		if !ok || pin == nil || (w.target != nil && identOf(s.Flow) == identOf(w.target.Flow)) {
			continue
		}
		alt := uint16(0)
		if a := v.Alternate(force); a != nil {
			alt = a.Port
		}
		idle := now.Sub(s.progress)
		pinned := s.External == pin.Port || (alt != 0 && s.External == alt)
		rejoined := w.target != nil && w.target.Endpoint() == s.Endpoint() && w.target.External != s.External
		if (pinned && rejoined && idle >= stalePinned) || (!pinned && idle >= staleOther) {
			if err := w.env.Table.Delete(s.Flow); err == nil {
				log.Printf("cs %s: released idle mapping %d toward %s:%d", w.env.Client, s.External, s.Server, s.DPort)
			}
		}
	}
}

func (w *Worker) syncReconnect() {
	if t := w.target; t != nil {
		w.mu.Lock()
		port := w.armed[t.Endpoint()]
		w.mu.Unlock()
		if port != 0 && t.External != port && t.ID != 0 {
			if err := w.env.Reconnect.Arm(t.Flow, port); err != nil {
				w.publish(func(s *Status) { s.Error = err.Error() })
			} else if err := w.env.Reconnect.Err(); err != nil {
				w.publish(func(s *Status) { s.Error = err.Error() })
			}
			return
		}
	}
	w.env.Reconnect.Disarm()
}

// describe derives the live server's status from what is saved; no measuring here.
func (w *Worker) describe() {
	t := w.target
	force := w.env.Settings.Force()
	if t == nil {
		w.publish(func(s *Status) {
			s.Phase, s.Server, s.DPort, s.CurrentPort = "waiting", "", 0, 0
			s.RescanAvailable, s.Name = false, ""
			s.Probes, s.Current = []Probe{}, nil
			showSaved(s, Server{}, force)
		})
		return
	}
	ep := t.Endpoint()
	v, ok := w.env.Store.Get(ep)
	w.publish(func(s *Status) {
		s.Server, s.DPort, s.CurrentPort = ep.Server.String(), ep.Port, t.External
		s.Name = v.Name
		if s.Name == "" {
			s.Name = w.names[ep]
		}
		s.RescanAvailable = true
		pin := showSaved(s, v, force)
		switch {
		case !ok:
			s.Phase = "detected"
			return
		case pin == nil:
			s.Phase = "kept"
		case pin.Port == t.External || (s.Alternate != nil && s.Alternate.Port == t.External):
			s.Phase = "applied"
		default:
			s.Phase = "ready"
		}
		if w.last != nil && w.last.ep == ep {
			s.Probes, s.Current = w.last.probes, w.last.current
		} else {
			s.Probes, s.Current = []Probe{}, nil
		}
	})
}

// showSaved copies a server's saved readings, pins and gain into s and
// returns the pin; a zero Server clears them.
func showSaved(s *Status, v Server, force bool) *Reading {
	s.Best, s.Auto, s.Reference = v.Best, v.Auto, v.Reference
	s.PinnedPort, s.Gain, s.Forced = 0, nil, false
	pin := v.Effective(force)
	s.Alternate = v.Alternate(force)
	if pin != nil {
		s.PinnedPort = pin.Port
		s.Forced = force && (v.Auto == nil || v.Auto.Port != pin.Port)
	}
	if v.Best != nil && v.Reference != nil {
		g := math.Round((v.Reference.RTT-v.Best.RTT)*100) / 100
		s.Gain = &g
	}
	return pin
}

func (w *Worker) scan(ep netx.Endpoint, preferred []uint16, progress func(int, int), cancel func() error) ([]Probe, error) {
	count := w.env.Settings.Count(game)
	flows, err := w.env.Table.Flows()
	if err != nil {
		return nil, err
	}
	busy := netx.Occupied(flows, w.public, ep)
	for p := range netx.LocalUDPPorts() {
		busy[p] = true
	}
	for p := range w.env.Others() {
		busy[p] = true
	}
	var ports []uint16
	for _, p := range preferred {
		if !busy[p] && len(ports) < count {
			busy[p] = true
			ports = append(ports, p)
		}
	}
	ports = append(ports, RandomPorts(count-len(ports), busy)...)
	total := len(ports)*scanRounds + scanRounds
	done := 0
	tick := func() { done++; progress(done, total) }
	probes, err := ProbePorts(w.env.Table, w.env.Table.DeleteLocal, w.public, ep, ports, scanRounds, cancel, tick)
	if err != nil {
		return nil, err
	}
	// One lucky median must not win: measure the winner again.
	best := -1
	for i, p := range probes {
		if p.RTT != nil && (best < 0 || *p.RTT < *probes[best].RTT) {
			best = i
		}
	}
	if best >= 0 {
		again, err := ProbePorts(w.env.Table, w.env.Table.DeleteLocal, w.public, ep, []uint16{probes[best].Port},
			scanRounds, cancel, tick)
		if err != nil {
			return nil, err
		}
		if again[0].RTT == nil {
			probes[best].RTT, probes[best].Error = nil, "the winner did not answer again"
		} else {
			worse := math.Max(*probes[best].RTT, *again[0].RTT)
			probes[best].RTT = &worse
			probes[best].Samples = append(probes[best].Samples, again[0].Samples...)
		}
	}
	progress(total, total)
	return probes, nil
}

// established waits for the game's connection before its port is measured.
// Linux marks UDP ASSURED about two seconds after the first reply, and a
// quick switch between servers is spotted sooner.
func (w *Worker) established(f netx.Flow) netx.Flow {
	deadline := time.Now().Add(5 * time.Second)
	for !f.Assured && time.Now().Before(deadline) && w.check() == nil {
		time.Sleep(200 * time.Millisecond)
		flows, err := w.env.Table.Flows()
		if err != nil {
			break
		}
		for _, g := range flows {
			if identOf(g) == identOf(f) {
				f = g
			}
		}
	}
	return f
}

func (w *Worker) liveScan() {
	t := *w.target
	ep := t.Endpoint()
	count := w.env.Settings.Count(game)
	w.env.Reconnect.Disarm()
	w.publish(func(s *Status) {
		s.Phase, s.Server, s.DPort, s.Probes, s.Current = "scanning", ep.Server.String(), ep.Port, []Probe{}, nil
		s.ScanCompleted, s.ScanTotal, s.Error, s.RescanAvailable = 0, count*scanRounds+scanRounds, "", false
	})
	log.Printf("cs %s: scanning %s:%d", w.env.Client, ep.Server, ep.Port)
	if err := w.check(); err != nil {
		w.scanned[ep] = false
		return
	}
	current := MeasureCurrent(w.env.Table, w.env.WAN, w.established(t.Flow), func() (bool, error) {
		addr, err := netx.WANAddress(w.env.WAN)
		return addr == t.Public, err
	})
	w.publish(func(s *Status) { s.Current = &current })
	v, saved := w.env.Store.Get(ep)
	probes, err := w.scan(ep, v.Preferred(), func(done, total int) {
		// A scan outlasts the device's claim: keep it, or the other game wakes up.
		w.env.Board.Claim(w.env.Client, game)
		w.publish(func(s *Status) { s.ScanCompleted, s.ScanTotal = done, total })
	}, w.check)
	if errors.Is(err, errInterrupted) || errors.Is(err, errStopping) {
		delete(w.scanned, ep)
		return
	}
	if err != nil {
		w.publish(func(s *Status) { s.Phase, s.Error = "error", err.Error() })
		return
	}
	var reference *Reading
	if current.RTT != nil {
		reference = &Reading{t.External, *current.RTT}
	}
	original := t.External
	if saved && ((v.Auto != nil && v.Auto.Port == t.External) || (v.Best != nil && v.Best.Port == t.External)) {
		original = 0 // the device is on a pinned port, not its own
	}
	_, ok := w.env.Store.Record(ep, probes, reference, original, true)
	w.heard(ep, probes)
	w.last = &lastScan{ep: ep, probes: probes, current: &current}
	if !ok {
		w.known[ep] = true
		w.publish(func(s *Status) { s.Error = "the server did not answer A2S probes" })
	}
	w.describe()
}

func (w *Worker) background(ep netx.Endpoint) {
	if !w.env.Store.Has(ep) {
		return
	}
	v, _ := w.env.Store.Get(ep)
	count := w.env.Settings.Count(game)
	w.mu.Lock()
	w.chk = &struct {
		ep netx.Endpoint
		Progress
	}{ep, Progress{0, count*scanRounds + scanRounds}}
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.chk = nil
		w.mu.Unlock()
	}()
	checked := time.Now()
	cancel := func() error {
		if err := w.check(); err != nil {
			return err
		}
		if time.Since(checked) >= busyCheck {
			checked = time.Now()
			if w.liveGame() {
				return errInterrupted
			}
		}
		return nil
	}
	probes, err := w.scan(ep, v.Preferred(), func(done, total int) {
		w.mu.Lock()
		if w.chk != nil {
			w.chk.Progress = Progress{done, total}
		}
		w.mu.Unlock()
	}, cancel)
	if errors.Is(err, errInterrupted) {
		w.queue = append([]netx.Endpoint{ep}, w.queue...)
		return
	}
	if err == nil {
		w.env.Store.Record(ep, probes, nil, 0, false)
		w.heard(ep, probes)
		// Arm a new pin on the next pass, not a poll later: until then the
		// list would show it as a busy port.
		w.signal()
	}
}

// heard notes whether a server answered its last check, for the list.
func (w *Worker) heard(ep netx.Endpoint, probes []Probe) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range probes {
		if p.RTT != nil {
			delete(w.silent, ep)
			return
		}
	}
	w.silent[ep] = true
}

// liveGame looks for a CS match starting on this device during a background check.
func (w *Worker) liveGame() bool {
	flows, err := w.env.Table.Flows()
	if err != nil {
		return false
	}
	now := time.Now()
	for _, f := range flows {
		old := w.flows[identOf(f)]
		if f.Client != w.env.Client || old == nil || !(w.env.Store.Has(f.Endpoint()) || w.known[f.Endpoint()]) {
			continue
		}
		elapsed := math.Max(now.Sub(old.at).Seconds(), 1)
		if float64(f.Packets-old.Packets) >= activePPS*elapsed && float64(f.ReplyPackets-old.ReplyPackets) >= activePPS*elapsed {
			return true
		}
	}
	return false
}

func (w *Worker) handleRemovals() {
	w.mu.Lock()
	var removals []netx.Endpoint
	kept := w.reqs[:0]
	for _, r := range w.reqs {
		if r.kind == "remove" {
			removals = append(removals, r.ep)
		} else {
			kept = append(kept, r)
		}
	}
	w.reqs = kept
	w.mu.Unlock()
	for _, ep := range removals {
		w.env.Store.Remove(ep)
		w.mu.Lock()
		delete(w.silent, ep)
		w.mu.Unlock()
		var queue []netx.Endpoint
		for _, q := range w.queue {
			if q != ep {
				queue = append(queue, q)
			}
		}
		w.queue = queue
		delete(w.known, ep)
		// A removed server is new again: the next join scans it.
		delete(w.scanned, ep)
		if w.last != nil && w.last.ep == ep {
			w.last = nil
		}
		if w.target != nil && w.target.Endpoint() == ep {
			// Do not save the same live connection again right away.
			w.ignored[identOf(w.target.Flow)] = true
			w.env.Board.Release(w.env.Client, game)
			w.target = nil
		}
	}
}

func (w *Worker) handleRequest() bool {
	w.mu.Lock()
	if len(w.reqs) == 0 {
		w.mu.Unlock()
		return false
	}
	r := w.reqs[0]
	w.reqs = w.reqs[1:]
	w.mu.Unlock()
	live := w.target != nil && (r.kind == "rescan" || w.target.Endpoint() == r.ep)
	switch {
	case live:
		w.liveScan()
	case r.kind == "refresh":
		var queue []netx.Endpoint
		for _, q := range w.queue {
			if q != r.ep {
				queue = append(queue, q)
			}
		}
		w.queue = queue
		w.background(r.ep)
	}
	return true
}

func (w *Worker) pause() {
	if !w.paused {
		w.env.Reconnect.Clear()
		w.env.Rejoin.Clear()
		w.env.Pins.Clear()
		w.env.Board.Release(w.env.Client, game)
		w.target, w.flows, w.primed, w.last = nil, map[ident]*seen{}, false, nil
		w.mu.Lock()
		w.armed = map[netx.Endpoint]uint16{}
		w.mu.Unlock()
		w.paused = true
	}
	w.publish(func(s *Status) {
		s.Phase, s.Server, s.DPort, s.CurrentPort, s.RescanAvailable = "disabled", "", 0, 0, false
		s.Probes, s.Current = []Probe{}, nil
	})
}

func (w *Worker) reset() {
	w.env.Reconnect.Disarm()
	w.env.Board.Release(w.env.Client, game)
	w.target, w.flows, w.primed, w.last = nil, map[ident]*seen{}, false, nil
	w.known, w.notCS = map[netx.Endpoint]bool{}, map[netx.Endpoint]time.Time{}
	w.ignored, w.scanned = map[ident]bool{}, map[netx.Endpoint]bool{}
	w.mu.Lock()
	kept := w.reqs[:0]
	for _, r := range w.reqs {
		if r.kind == "remove" {
			kept = append(kept, r)
		}
	}
	w.reqs = kept
	w.silent = map[netx.Endpoint]bool{}
	w.stat = Status{Phase: "waiting", Probes: []Probe{}}
	w.mu.Unlock()
}

func (w *Worker) tick() {
	if g := w.env.Settings.Generation(); g != w.generation {
		w.generation = g
		w.reset()
	}
	if !w.env.Settings.Active(game) {
		w.pause()
		return
	}
	if w.paused {
		w.paused = false
		w.publish(func(s *Status) { s.Phase, s.Error = "waiting", "" })
	}
	public, err := netx.WANAddress(w.env.WAN)
	if err != nil {
		w.publish(func(s *Status) { s.Phase, s.Error = "error", err.Error() })
		return
	}
	w.public = public
	flows, err := w.env.Table.Flows()
	if err != nil {
		w.publish(func(s *Status) { s.Phase, s.Error = "error", err.Error() })
		return
	}
	w.handleRemovals()
	if other := w.env.Board.Other(w.env.Client, game); other != "" {
		w.target, w.last = nil, nil
		w.env.Reconnect.Disarm()
		w.suspended = true
		w.publish(func(s *Status) {
			s.Phase, s.OtherGame, s.Server, s.DPort, s.CurrentPort, s.RescanAvailable = "suspended", other, "", 0, 0, false
			s.Probes, s.Current = []Probe{}, nil
		})
		w.syncPins(flows)
		return
	}
	if w.suspended {
		w.suspended = false
		w.publish(func(s *Status) { s.OtherGame = "" })
	}
	now := time.Now()
	w.observe(flows, now)
	w.syncPins(flows)
	w.releaseStale(now)
	w.syncReconnect()
	w.describe()
	if w.handleRequest() {
		return
	}
	if t := w.target; t != nil {
		// A new server, or a saved one still on the device's own port, is
		// scanned on join so it gets a pin.
		ep := t.Endpoint()
		v, saved := w.env.Store.Get(ep)
		if !w.scanned[ep] && (!saved || v.Effective(w.env.Settings.Force()) == nil) {
			w.scanned[ep] = true
			w.liveScan()
		}
	} else if len(w.queue) > 0 {
		ep := w.queue[0]
		w.queue = w.queue[1:]
		w.background(ep)
	} else {
		w.name(now)
	}
}

// name asks one saved server without a name for its A2S info.
func (w *Worker) name(now time.Time) {
	for _, v := range w.env.Store.Entries() {
		ep := v.Endpoint()
		if v.Name != "" || now.Sub(w.asked[ep]) < notCSFor {
			continue
		}
		w.asked[ep] = now
		busy := netx.LocalUDPPorts()
		if flows, err := w.env.Table.Flows(); err == nil {
			for p := range netx.Occupied(flows, w.public, ep) {
				busy[p] = true
			}
		}
		probes, err := ProbePorts(w.env.Table, w.env.Table.DeleteLocal, w.public, ep, RandomPorts(1, busy), 1,
			func() error { return nil }, func() {})
		if err == nil && len(probes) == 1 && probes[0].Info != nil {
			w.env.Store.SetName(ep, probes[0].Info.Name)
		}
		return
	}
}

// Run serves one device until Stop.
func (w *Worker) Run() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			w.env.Reconnect.Clear()
			w.env.Rejoin.Clear()
			w.env.Pins.Clear()
			w.env.Board.Release(w.env.Client, game)
			return
		default:
		}
		w.tick()
		select {
		case <-w.wake:
		case <-w.stop:
		case <-time.After(poll):
		}
	}
}

func (w *Worker) Stop() {
	close(w.stop)
	<-w.done
}
