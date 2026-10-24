package cs

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/demyaha/brutter/internal/config"
	"github.com/demyaha/brutter/internal/netx"
)

const (
	maxServers = 64
	maxPorts   = 5
	serverAge  = 60 * 24 * time.Hour
	minGainMS  = 2.0
	flushEvery = 10 * time.Minute
)

// Reading is a port with its round trip.
type Reading struct {
	Port uint16  `json:"port"`
	RTT  float64 `json:"rtt_ms"`
}

func (r *Reading) valid() bool {
	return r != nil && r.Port >= 1024 && !math.IsNaN(r.RTT) && r.RTT > 0 && r.RTT <= 3000
}

// Server is one saved CS server.
type Server struct {
	Server     string    `json:"server"`
	DPort      uint16    `json:"dport"`
	Name       string    `json:"name,omitempty"`
	LastPlayed float64   `json:"last_played"`
	CheckedAt  *float64  `json:"checked_at"`
	Ports      []Reading `json:"ports"`
	Best       *Reading  `json:"best"`
	// Auto is the port automatic mode pins: one that beat the device's own
	// port by 2 ms. Nil keeps the port NAT would pick.
	Auto      *Reading `json:"auto"`
	Reference *Reading `json:"reference"` // the device's own port, measured
	Original  uint16   `json:"original_port,omitempty"`
}

func (s *Server) Endpoint() netx.Endpoint {
	return netx.Endpoint{Server: netip.MustParseAddr(s.Server), Port: s.DPort}
}

func seconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func copyReading(r *Reading) *Reading {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

func (s Server) clone() Server {
	c := s
	c.Ports = append([]Reading(nil), s.Ports...)
	c.Best, c.Auto, c.Reference = copyReading(s.Best), copyReading(s.Auto), copyReading(s.Reference)
	if s.CheckedAt != nil {
		v := *s.CheckedAt
		c.CheckedAt = &v
	}
	return c
}

// Choose is automatic mode's decision. A server without a pin gets the
// fastest port, on join or on a manual check. A pin moves only for a gain of
// 2 ms over a port measured in the same pass: the device's own port when it
// played on one, else the pin itself, so a noisy scan does not shift it.
func Choose(best, reference, previous *Reading, fresh []Reading) *Reading {
	if best == nil {
		return copyReading(previous)
	}
	if previous == nil {
		return copyReading(best)
	}
	var pinned *Reading
	for _, p := range fresh {
		if p.Port == previous.Port {
			pinned = &Reading{p.Port, p.RTT}
		}
	}
	base := reference
	if base == nil || base.Port == best.Port {
		base = pinned
	}
	if base == nil || best.Port != base.Port && math.Round((base.RTT-best.RTT)*100)/100 >= minGainMS {
		return copyReading(best)
	}
	if pinned != nil {
		return pinned
	}
	return copyReading(previous)
}

// Store is the saved server list of one device.
type Store struct {
	mu      sync.Mutex
	path    string
	records map[netx.Endpoint]*Server
	now     func() time.Time
	flushed time.Time
	Warning string
}

type file struct {
	Version int               `json:"version"`
	Servers []json.RawMessage `json:"servers"`
}

func OpenStore(path string, now func() time.Time) *Store {
	s := &Store{path: path, records: map[netx.Endpoint]*Server{}, now: now, flushed: now()}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.Warning = err.Error()
		}
		return s
	}
	if err := s.load(data); err != nil {
		s.Warning = err.Error()
		s.records = map[netx.Endpoint]*Server{}
	}
	return s
}

func (s *Store) load(data []byte) error {
	var f file
	if len(data) > 512*1024 {
		return errors.New("saved server file is too large")
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	if f.Version != 1 && f.Version != 2 {
		return errors.New("unsupported saved server format")
	}
	now := seconds(s.now())
	for _, raw := range f.Servers {
		var v Server
		if json.Unmarshal(raw, &v) != nil {
			continue
		}
		addr, err := netip.ParseAddr(v.Server)
		if err != nil || !netx.IsPublic(addr) || v.DPort == 0 {
			continue
		}
		if v.LastPlayed < now-serverAge.Seconds() || v.LastPlayed > now+300 {
			continue
		}
		var ports []Reading
		seen := map[uint16]bool{}
		for i := range v.Ports {
			if p := &v.Ports[i]; p.valid() && !seen[p.Port] {
				seen[p.Port] = true
				ports = append(ports, Reading{p.Port, p.RTT})
			}
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i].RTT < ports[j].RTT })
		if len(ports) > maxPorts {
			ports = ports[:maxPorts]
		}
		v.Server, v.Ports = addr.String(), ports
		v.Best = nil
		if len(ports) > 0 {
			v.Best = &Reading{ports[0].Port, ports[0].RTT}
		}
		if f.Version == 1 {
			// Version 1 prepared its fastest port for every saved server.
			v.Auto, v.Reference, v.Original = copyReading(v.Best), nil, 0
		}
		if !v.Auto.valid() {
			v.Auto = nil
		}
		if !v.Reference.valid() {
			v.Reference = nil
		}
		if v.Original < 1024 {
			v.Original = 0
		}
		ep := netx.Endpoint{Server: addr, Port: v.DPort}
		// Version 1 kept one copy per WAN address; keep the latest.
		if old, ok := s.records[ep]; ok && old.LastPlayed >= v.LastPlayed {
			continue
		}
		copied := v
		s.records[ep] = &copied
	}
	s.trim()
	return nil
}

func (s *Store) trim() {
	now := seconds(s.now())
	list := make([]*Server, 0, len(s.records))
	for _, v := range s.records {
		if now-v.LastPlayed <= serverAge.Seconds() {
			list = append(list, v)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LastPlayed > list[j].LastPlayed })
	if len(list) > maxServers {
		list = list[:maxServers]
	}
	s.records = map[netx.Endpoint]*Server{}
	for _, v := range list {
		s.records[v.Endpoint()] = v
	}
}

func (s *Store) Has(ep netx.Endpoint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.records[ep]
	return ok
}

func (s *Store) Get(ep netx.Endpoint) (Server, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.records[ep]
	if !ok {
		return Server{}, false
	}
	return v.clone(), true
}

// Entries are the saved servers, most recently played first.
func (s *Store) Entries() []Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Server, 0, len(s.records))
	for _, v := range s.records {
		out = append(out, v.clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastPlayed != out[j].LastPlayed {
			return out[i].LastPlayed > out[j].LastPlayed
		}
		return out[i].Server < out[j].Server
	})
	return out
}

// Effective is the port new connections should use; 0 keeps NAT's choice.
func (v Server) Effective(force bool) *Reading {
	if force {
		return copyReading(v.Best)
	}
	return copyReading(v.Auto)
}

// Alternate is the second pinned port: the next fastest measured one, if it
// is within 2 ms of the pinned port. A quick rejoin uses it while the server
// still holds the previous connection on the first.
func (v Server) Alternate(force bool) *Reading {
	pin := v.Effective(force)
	if pin == nil {
		return nil
	}
	for _, p := range v.Ports {
		if p.Port != pin.Port && p.RTT <= pin.RTT+minGainMS {
			return &Reading{p.Port, p.RTT}
		}
	}
	return nil
}

// Preferred are ports worth measuring again: earlier winners and the device's own.
func (v Server) Preferred() []uint16 {
	var ports []uint16
	add := func(p uint16) {
		for _, q := range ports {
			if q == p {
				return
			}
		}
		if p >= 1024 {
			ports = append(ports, p)
		}
	}
	for _, p := range v.Ports {
		add(p.Port)
	}
	if v.Auto != nil {
		add(v.Auto.Port)
	}
	add(v.Original)
	return ports
}

// Record stores a finished scan. reference is the device's port measured now;
// without one, the device's own port measured from the router stands in.
func (s *Store) Record(ep netx.Endpoint, probes []Probe, reference *Reading, original uint16, played bool) (Server, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []Reading
	for _, p := range probes {
		if r := (&Reading{p.Port, 0}); p.RTT != nil {
			r.RTT = *p.RTT
			if r.valid() {
				fresh = append(fresh, *r)
			}
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].RTT < fresh[j].RTT })
	old, ok := s.records[ep]
	if len(fresh) == 0 && !ok {
		return Server{}, false
	}
	now := seconds(s.now())
	v := Server{Server: ep.Server.String(), DPort: ep.Port, LastPlayed: now}
	if ok {
		v = old.clone()
	}
	if original >= 1024 {
		v.Original = original
	}
	for _, p := range probes {
		if p.Info != nil && p.Info.Name != "" {
			v.Name = p.Info.Name
		}
	}
	if reference == nil && v.Original != 0 {
		for _, p := range fresh {
			if p.Port == v.Original {
				reference = &Reading{p.Port, p.RTT}
			}
		}
	}
	if !reference.valid() {
		reference = nil
	}
	if len(fresh) > 0 {
		v.Ports = fresh
		if len(v.Ports) > maxPorts {
			v.Ports = v.Ports[:maxPorts]
		}
		v.Best = &Reading{fresh[0].Port, fresh[0].RTT}
		if reference != nil {
			v.Reference = copyReading(reference)
		}
		v.Auto = Choose(v.Best, reference, v.Auto, fresh)
	}
	v.CheckedAt = &now
	if played {
		v.LastPlayed = now
	}
	s.records[ep] = &v
	s.trim()
	s.flush()
	return v.clone(), true
}

// Touch marks a server as played; it reaches flash at most every ten minutes.
func (s *Store) Touch(ep netx.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.records[ep]; ok {
		v.LastPlayed = seconds(s.now())
		if s.now().Sub(s.flushed) >= flushEvery {
			s.flush()
		}
	}
}

// SetName records a server's A2S name.
func (s *Store) SetName(ep netx.Endpoint, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.records[ep]; ok && name != "" && v.Name != name {
		v.Name = name
		s.flush()
	}
}

func (s *Store) Remove(ep netx.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, ep)
	s.flush()
}

func (s *Store) flush() {
	list := make([]*Server, 0, len(s.records))
	for _, v := range s.records {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LastPlayed > list[j].LastPlayed })
	data, err := json.Marshal(struct {
		Version int       `json:"version"`
		Servers []*Server `json:"servers"`
	}{2, list})
	if err == nil {
		if err = config.WriteFile(s.path, data); err == nil {
			s.flushed = s.now()
		}
	}
	if err != nil {
		s.Warning = err.Error()
	}
}
