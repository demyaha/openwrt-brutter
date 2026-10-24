package valorant

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// A sample above this is a busy server or a lost reply, not path latency.
	maxSampleMS = 300
	// Emit a join that showed a Challenge even if its Ack was never captured.
	ackGrace   = 3 * time.Second
	sessionTTL = 5 * time.Minute
	maxTracked = 16
)

// Key is the device side of a game connection, which NAT changes never touch.
type Key struct {
	Server       netip.Addr
	SPort, DPort uint16
}

// Sample is one handshake round trip. RTT is nil when a retransmission made
// the pairing ambiguous: the exchange happened, its timing is unknown.
type Sample struct {
	Kind       string    `json:"kind"`
	RTT        *float64  `json:"rtt_ms"`
	SentAt     time.Time `json:"-"`
	ReceivedAt time.Time `json:"-"`
}

// Event is a detected join.
type Event struct {
	Key
	Template   []byte
	Baseline   *float64
	Samples    []Sample
	CapturedAt time.Time
	StartedAt  time.Time
	Source     string // "handshake" or "recovered"
}

type pending struct {
	sent      time.Time
	kind      uint8
	ambiguous bool
}

type session struct {
	cid         uint8
	outer       []byte
	template    []byte
	started     time.Time
	touched     time.Time
	initials    map[uint8]time.Time
	pending     map[[2]uint8]*pending
	samples     []Sample
	challengeAt time.Time
	emitted     bool
	latest      *Sample
}

// Tracker correlates one device's handshake packets by tuple, counter and session.
type Tracker struct {
	mu       sync.Mutex
	sessions map[Key]*session
	Counts   map[string]int
}

func NewTracker() *Tracker {
	return &Tracker{sessions: map[Key]*session{}, Counts: map[string]int{}}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// Baseline is the best round trip of a join; a busy server only inflates samples.
// Response→Ack matches what players see; Initial→Challenge is the fallback.
func Baseline(samples []Sample) *float64 {
	var best, fallback *float64
	for _, s := range samples {
		if s.RTT == nil {
			continue
		}
		v := *s.RTT
		if s.Kind == "challenge" {
			if fallback == nil || v < *fallback {
				fallback = &v
			}
		} else if best == nil || v < *best {
			best = &v
		}
	}
	if best != nil {
		return best
	}
	return fallback
}

func (t *Tracker) newSession(k Key, p Packet, ts time.Time) *session {
	if len(t.sessions) >= maxTracked {
		var oldest Key
		var at time.Time
		for key, s := range t.sessions {
			if at.IsZero() || s.started.Before(at) {
				oldest, at = key, s.started
			}
		}
		delete(t.sessions, oldest)
	}
	s := &session{
		cid: p.CID, outer: append([]byte(nil), p.Payload[:8]...), started: ts, touched: ts,
		initials: map[uint8]time.Time{}, pending: map[[2]uint8]*pending{},
	}
	t.sessions[k] = s
	return s
}

func (t *Tracker) event(k Key, s *session, ts time.Time) *Event {
	s.emitted = true
	t.Counts["emitted"]++
	template := s.template
	if template == nil {
		template, _ = RecoveryInitial(s.outer, s.cid)
	}
	samples := append([]Sample(nil), s.samples...)
	return &Event{Key: k, Template: template, Baseline: Baseline(samples), Samples: samples,
		CapturedAt: ts, StartedAt: s.started, Source: "handshake"}
}

var kindNames = map[uint8]string{KindInitial: "initial", KindChallenge: "challenge",
	KindResponse: "response", KindAck: "ack", KindRestartResponse: "restart"}

// Feed processes one handshake packet and returns a join once it is complete.
func (t *Tracker) Feed(p Packet, ts time.Time) *Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	if name, ok := kindNames[p.Kind]; ok {
		t.Counts[name]++
	}
	for k, s := range t.sessions {
		if ts.Sub(s.touched) >= sessionTTL {
			delete(t.sessions, k)
		}
	}
	k := Key{p.Server, p.SPort, p.DPort}
	s := t.sessions[k]
	if p.Out && p.Kind == KindInitial && !p.Restart {
		// A fresh Initial after a finished join is a new session on a reused tuple.
		if s == nil || s.emitted || s.cid != p.CID {
			s = t.newSession(k, p, ts)
		}
		if p.Complete && s.template == nil {
			if tmpl, err := Initial(p.Payload, 0); err == nil {
				s.template = tmpl
			}
		}
		s.initials[p.Seq] = ts
	}
	if s == nil {
		if !p.Out || (p.Kind != KindResponse && p.Kind != KindRestartResponse) {
			return nil
		}
		// Joined before the capture started: keep only routing metadata.
		s = t.newSession(k, p, ts)
	}
	s.touched = ts
	if p.CID != s.cid {
		return nil
	}
	if p.Out {
		if p.Kind == KindResponse || p.Kind == KindRestartResponse {
			// Correlation metadata only; Response and cookie bytes are never kept.
			id := [2]uint8{p.Seq, p.Session}
			if q, ok := s.pending[id]; ok {
				q.ambiguous = true
				t.Counts["retransmitted"]++
			} else if len(s.pending) < 8 {
				s.pending[id] = &pending{sent: ts, kind: p.Kind}
			}
		}
		return nil
	}
	if p.Kind == KindChallenge && !p.Restart {
		sent, ok := s.initials[p.Seq]
		delete(s.initials, p.Seq)
		if s.challengeAt.IsZero() {
			s.challengeAt = ts
		}
		if rtt := ms(ts.Sub(sent)); ok && rtt >= 1 && rtt <= maxSampleMS {
			s.samples = append(s.samples, Sample{Kind: "challenge", RTT: &rtt, SentAt: sent, ReceivedAt: ts})
		}
		return nil
	}
	if p.Kind != KindAck {
		return nil
	}
	id := [2]uint8{p.Seq, p.Session}
	q, ok := s.pending[id]
	delete(s.pending, id)
	if !ok {
		t.Counts["unmatched"]++
	} else {
		// A retransmitted Response makes the pairing ambiguous: the join still
		// counts, its round trip does not.
		sample := Sample{Kind: "ack", SentAt: q.sent, ReceivedAt: ts}
		if q.kind == KindRestartResponse {
			sample.Kind = "restart"
		}
		if rtt := ms(ts.Sub(q.sent)); !q.ambiguous && rtt >= 1 && rtt <= maxSampleMS {
			sample.RTT = &rtt
		}
		if q.kind == KindRestartResponse {
			copied := sample
			s.latest = &copied
		}
		if sample.RTT != nil && !s.emitted {
			s.samples = append(s.samples, sample)
		}
	}
	if !s.emitted {
		return t.event(k, s, ts)
	}
	return nil
}

// Due returns joins whose Challenge was seen but whose Ack never reached the capture.
func (t *Tracker) Due(now time.Time) []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	var events []Event
	for k, s := range t.sessions {
		if !s.emitted && !s.challengeAt.IsZero() && now.Sub(s.challengeAt) >= ackGrace {
			events = append(events, *t.event(k, s, now))
		}
	}
	return events
}

// Known returns a probe template for a tuple seen during this capture.
func (t *Tracker) Known(k Key) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[k]
	if s == nil {
		return nil
	}
	if s.template != nil {
		return s.template
	}
	tmpl, _ := RecoveryInitial(s.outer, s.cid)
	return tmpl
}

// Latest is the restart exchange that followed a NAT change made at after.
func (t *Tracker) Latest(k Key, after time.Time) *Sample {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[k]
	if s == nil || s.latest == nil || s.latest.SentAt.Before(after) {
		return nil
	}
	copied := *s.latest
	return &copied
}

// Stats copies the packet counters for the dashboard.
func (t *Tracker) Stats() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]int, len(t.Counts))
	for k, v := range t.Counts {
		out[k] = v
	}
	return out
}
