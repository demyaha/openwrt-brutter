package valorant

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"sort"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

const (
	interval     = 50 * time.Millisecond  // 20 requests per second
	slowInterval = 150 * time.Millisecond // after a round with many lost replies
	replyTimeout = 600 * time.Millisecond
	rounds       = 2
	finalists    = 5
	confirmRound = 4
)

// ErrCancelled stops a scan for Reset, Off or a newer match.
var ErrCancelled = errors.New("scan cancelled")

// Probe is one free port's result.
type Probe struct {
	Port    uint16     `json:"port"`
	RTT     *float64   `json:"rtt_ms"`
	Samples []*float64 `json:"samples_ms"`
	final   bool
}

type reply struct {
	port uint16
	data []byte
	at   time.Time
}

// Prober sends zero-auth Initials from free router ports to the match's
// server; the device's own port is never used.
type Prober struct {
	Server    netip.AddrPort
	Public    netip.Addr
	template  []byte
	cid       uint8
	cancelled func() bool
	sockets   map[uint16]*netx.Socket
	seq       map[uint16]uint8
	replies   chan reply
	interval  time.Duration
	requests  int
	limit     int
}

func NewProber(public netip.Addr, server netip.AddrPort, template []byte, cancelled func() bool) (*Prober, error) {
	h, ok := ParseHeader(template, true, len(template))
	if !ok {
		return nil, errInitial
	}
	if _, err := Initial(template, 0); err != nil {
		return nil, err
	}
	return &Prober{Server: server, Public: public, template: template, cid: h.CID,
		cancelled: cancelled, sockets: map[uint16]*netx.Socket{}, seq: map[uint16]uint8{},
		replies: make(chan reply, 256), interval: interval}, nil
}

// Allocate binds count free ports, skipping any already mapped toward the server.
func (p *Prober) Allocate(count int, occupied map[uint16]bool) error {
	for tries := 0; len(p.sockets) < count && tries < count*6; tries++ {
		s, err := netx.Dial(netip.AddrPortFrom(p.Public, 0), p.Server)
		if err != nil {
			return err
		}
		if occupied[s.Port] {
			s.Close()
			continue
		}
		p.sockets[s.Port] = s
		// Each socket owns an increasing 8-bit counter: a late reply never
		// matches a newer request on the same port.
		p.seq[s.Port] = uint8(16 + rand.IntN(32))
		go p.read(s)
	}
	if len(p.sockets) == 0 {
		return errors.New("no free probe ports available")
	}
	return nil
}

func (p *Prober) read(s *netx.Socket) {
	for {
		data, at, err := s.Receive(time.Now().Add(time.Hour))
		if err != nil {
			if netx.IsTimeout(err) {
				continue
			}
			return // closed
		}
		select {
		case p.replies <- reply{s.Port, append([]byte(nil), data...), at}:
		default: // never block on a flood
		}
	}
}

type outstanding struct {
	seq  uint8
	sent time.Time
}

// round sends one request per port at the paced interval and collects
// replies in between.
func (p *Prober) round(ports []uint16, done func()) (map[uint16]*float64, error) {
	result := map[uint16]*float64{}
	pending := map[uint16]outstanding{}
	queue := append([]uint16(nil), ports...)
	next := time.Now()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for len(queue) > 0 || len(pending) > 0 {
		if p.cancelled() {
			return nil, ErrCancelled
		}
		now := time.Now()
		if len(queue) > 0 && !now.Before(next) {
			port := queue[0]
			queue = queue[1:]
			p.requests++
			if p.seq[port] == 255 || (p.limit > 0 && p.requests > p.limit) {
				return nil, errors.New("probe request limit reached")
			}
			p.seq[port]++
			payload, _ := Initial(p.template, p.seq[port])
			sent, err := p.sockets[port].Send(payload)
			if err != nil {
				result[port] = nil
				done()
			} else {
				pending[port] = outstanding{p.seq[port], sent}
			}
			next = next.Add(p.interval)
			if next.Before(sent) {
				next = sent
			}
		}
		wake := time.Now().Add(time.Hour)
		if len(queue) > 0 {
			wake = next
		}
		for _, o := range pending {
			if d := o.sent.Add(replyTimeout); d.Before(wake) {
				wake = d
			}
		}
		timer.Reset(time.Until(wake))
		select {
		case r := <-p.replies:
			o, ok := pending[r.port]
			if ok && IsChallenge(r.data, o.seq, p.cid) {
				delete(pending, r.port)
				rtt := ms(r.at.Sub(o.sent))
				if rtt > 0 && rtt < ms(replyTimeout) {
					result[r.port] = &rtt
				} else {
					result[r.port] = nil
				}
				done()
			}
		case <-timer.C:
		}
		now = time.Now()
		for port, o := range pending {
			if now.Sub(o.sent) >= replyTimeout {
				delete(pending, port)
				result[port] = nil
				done()
			}
		}
	}
	return result, nil
}

// Summary is the median of the replies, if enough of the requests were answered.
func Summary(samples []*float64) *float64 {
	var valid []float64
	for _, s := range samples {
		if s != nil {
			valid = append(valid, *s)
		}
	}
	if len(valid) == 0 || len(valid)*5 < len(samples)*3 {
		return nil
	}
	m := Median(valid)
	return &m
}

// slowest is the highest round trip among the ports that answered.
func slowest(probes []Probe) *float64 {
	var top *float64
	for _, p := range probes {
		if p.RTT != nil && (top == nil || *p.RTT > *top) {
			top = p.RTT
		}
	}
	return top
}

func Median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Measure makes two passes over every port, then repeated passes over the
// finalists. progress gets (done, total).
func (p *Prober) Measure(progress func(int, int)) ([]Probe, *Probe, error) {
	ports := make([]uint16, 0, len(p.sockets))
	for port := range p.sockets {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	final := finalists
	if final > len(ports) {
		final = len(ports)
	}
	total := len(ports)*rounds + final*confirmRound
	p.limit = total + 8
	completed := 0
	done := func() {
		completed++
		progress(completed, total)
	}
	samples := map[uint16][]*float64{}
	for r := 0; r < rounds; r++ {
		order := append([]uint16(nil), ports...)
		rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		result, err := p.round(order, done)
		if err != nil {
			return nil, nil, err
		}
		lost := 0
		for _, port := range ports {
			samples[port] = append(samples[port], result[port])
			if result[port] == nil {
				lost++
			}
		}
		if r == 0 && lost*10 > len(ports)*3 {
			p.interval = slowInterval
		}
	}
	median := func(port uint16) float64 {
		var v []float64
		for _, s := range samples[port] {
			if s != nil {
				v = append(v, *s)
			}
		}
		if len(v) == 0 {
			return 1e9
		}
		return Median(v)
	}
	ranked := append([]uint16(nil), ports...)
	sort.Slice(ranked, func(i, j int) bool { return median(ranked[i]) < median(ranked[j]) })
	var top []uint16
	for _, port := range ranked[:final] {
		if median(port) < 1e9 {
			top = append(top, port)
		}
	}
	for r := 0; r < confirmRound && len(top) > 0; r++ {
		order := append([]uint16(nil), top...)
		rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		result, err := p.round(order, done)
		if err != nil {
			return nil, nil, err
		}
		for _, port := range top {
			samples[port] = append(samples[port], result[port])
		}
	}
	progress(total, total)
	isTop := map[uint16]bool{}
	for _, port := range top {
		isTop[port] = true
	}
	probes := make([]Probe, 0, len(ports))
	var best *Probe
	for _, port := range ports {
		pr := Probe{Port: port, RTT: Summary(samples[port]), Samples: samples[port], final: isTop[port]}
		probes = append(probes, pr)
		answered := 0
		for _, s := range pr.Samples {
			if s != nil {
				answered++
			}
		}
		if pr.final && pr.RTT != nil && answered >= 4 && (best == nil || *pr.RTT < *best.RTT) {
			copied := pr
			best = &copied
		}
	}
	return probes, best, nil
}

// MeasureOne binds port itself and times n requests from it, one at a time.
func (p *Prober) MeasureOne(port uint16, n int) (*Probe, error) {
	s, err := netx.Dial(netip.AddrPortFrom(p.Public, port), p.Server)
	if err != nil {
		return nil, err
	}
	p.sockets[port] = s
	p.seq[port] = uint8(16 + rand.IntN(32))
	go p.read(s)
	p.limit = p.requests + n
	var samples []*float64
	for i := 0; i < n; i++ {
		result, err := p.round([]uint16{port}, func() {})
		if err != nil {
			return nil, err
		}
		samples = append(samples, result[port])
	}
	return &Probe{Port: port, RTT: Summary(samples), Samples: samples}, nil
}

// Close releases the ports and removes the router's own probe entries.
func (p *Prober) Close(table interface {
	DeleteLocal(netip.Addr, uint16, netx.Endpoint)
}) {
	for port, s := range p.sockets {
		s.Close()
		if table != nil {
			table.DeleteLocal(p.Public, port, netx.Endpoint{Server: p.Server.Addr(), Port: p.Server.Port()})
		}
	}
	p.sockets = map[uint16]*netx.Socket{}
}
