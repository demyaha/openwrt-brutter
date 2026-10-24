package valorant

import (
	"bytes"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/demyaha/brutter/internal/netx"
)

type pk struct {
	out                              bool
	kind, seq, cid, session, version uint8
	restart                          bool
	cookie                           uint64
}

// payload builds a synthetic v3/4 handshake: no captured game data.
func payload(o pk) []byte {
	if o.cid == 0 {
		o.cid = 3
	}
	if o.version == 0 {
		o.version = 4
	}
	base, size := inBase, 69
	if o.out {
		base, size = outBase, 73
	}
	p := make([]byte, size)
	setBits(p, base, 2, uint64(o.session))
	setBits(p, base+2, 3, uint64(o.cid))
	setBits(p, base+5, 1, 1)
	if o.restart {
		setBits(p, base+6, 1, 1)
	}
	setBits(p, base+7, 8, 3)
	setBits(p, base+15, 8, uint64(o.version))
	setBits(p, base+23, 8, uint64(o.kind))
	setBits(p, base+31, 8, uint64(o.seq))
	if o.cookie != 0 {
		setBits(p, base+152, 64, o.cookie)
	}
	return p
}

var (
	client = netip.MustParseAddr("192.168.1.100")
	server = netip.MustParseAddr("203.0.113.10")
)

func packet(o pk) Packet {
	src, dst, sp, dp := client, server, uint16(51832), uint16(7222)
	if !o.out {
		src, dst, sp, dp = server, client, 7222, 51832
	}
	p, ok := Decode(netx.Datagram(src, dst, sp, dp, payload(o), 42))
	if !ok {
		panic("fixture did not decode")
	}
	return p
}

func at(s float64) time.Time { return time.Unix(0, 0).Add(time.Duration(s * float64(time.Second))) }

func TestOnlyZeroAuthInitialCanBeReplayed(t *testing.T) {
	got, err := Initial(payload(pk{out: true, seq: 3}), 200)
	if err != nil || !bytes.Equal(got, payload(pk{out: true, seq: 200})) {
		t.Fatalf("initial: %v", err)
	}
	for name, p := range map[string][]byte{
		"response": payload(pk{out: true, kind: 2}),
		"restart":  payload(pk{out: true, restart: true}),
		"cookie":   payload(pk{out: true, cookie: 1}),
		"version":  payload(pk{out: true, version: 5}),
		"short":    payload(pk{out: true})[:20],
	} {
		if _, err := Initial(p, 200); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestChallengeNeedsCounterClientAndVersion(t *testing.T) {
	if !IsChallenge(payload(pk{kind: 1, seq: 200}), 200, 3) {
		t.Fatal("valid challenge rejected")
	}
	for _, p := range [][]byte{
		payload(pk{kind: 1, seq: 199}), payload(pk{kind: 3, seq: 200}),
		payload(pk{kind: 1, seq: 200, cid: 2}), payload(pk{kind: 1, seq: 200, version: 5}), nil,
	} {
		if IsChallenge(p, 200, 3) {
			t.Error("bad challenge accepted")
		}
	}
}

func TestRecoveryInitialKeepsOnlyRoutingPrefix(t *testing.T) {
	outer := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	tmpl, err := RecoveryInitial(outer, 5)
	if err != nil || !bytes.Equal(tmpl[:8], outer) || len(tmpl) != 76 {
		t.Fatalf("template: %v", err)
	}
	h, ok := ParseHeader(tmpl, true, len(tmpl))
	if !ok || h.Kind != KindInitial || h.CID != 5 {
		t.Fatalf("header %+v", h)
	}
}

func TestResponseAckIsTheBaseline(t *testing.T) {
	tr := NewTracker()
	if tr.Feed(packet(pk{out: true, seq: 3}), at(100)) != nil {
		t.Fatal("initial emitted")
	}
	tr.Feed(packet(pk{kind: 1, seq: 3}), at(100.4)) // slow first Challenge: no sample
	tr.Feed(packet(pk{out: true, kind: 2, seq: 4, cookie: 123}), at(101.007))
	e := tr.Feed(packet(pk{kind: 3, seq: 4}), at(101.0667))
	if e == nil || e.Baseline == nil || math.Abs(*e.Baseline-59.7) > 0.01 {
		t.Fatalf("event %+v", e)
	}
	if !bytes.Equal(e.Template, payload(pk{out: true, seq: 0})) || e.SPort != 51832 {
		t.Fatal("template or tuple wrong")
	}
	if tr.Feed(packet(pk{kind: 3, seq: 4}), at(101.07)) != nil {
		t.Fatal("duplicate ack emitted twice")
	}
}

func TestRetransmittedResponseStillDetectsTheJoin(t *testing.T) {
	tr := NewTracker()
	tr.Feed(packet(pk{out: true, seq: 3}), at(100))
	tr.Feed(packet(pk{kind: 1, seq: 3}), at(100.05))
	tr.Feed(packet(pk{out: true, kind: 2, seq: 4}), at(100.1))
	tr.Feed(packet(pk{out: true, kind: 2, seq: 4}), at(101.1))
	e := tr.Feed(packet(pk{kind: 3, seq: 4}), at(101.15))
	if e == nil {
		t.Fatal("busy-server join was dropped")
	}
	if e.Baseline == nil || math.Abs(*e.Baseline-50) > 0.01 {
		t.Fatalf("baseline should fall back to Initial→Challenge, got %v", e.Baseline)
	}
}

func TestChallengeWithoutAckEmitsAfterGrace(t *testing.T) {
	tr := NewTracker()
	tr.Feed(packet(pk{out: true, seq: 3}), at(100))
	tr.Feed(packet(pk{kind: 1, seq: 3}), at(100.06))
	if len(tr.Due(at(102))) != 0 {
		t.Fatal("emitted too early")
	}
	events := tr.Due(at(103.1))
	if len(events) != 1 || events[0].Baseline == nil || math.Abs(*events[0].Baseline-60) > 0.01 {
		t.Fatalf("due %+v", events)
	}
	if len(tr.Due(at(110))) != 0 {
		t.Fatal("emitted twice")
	}
}

func TestWrongClientOrCounterCannotPair(t *testing.T) {
	tr := NewTracker()
	tr.Feed(packet(pk{out: true, seq: 3}), at(100))
	tr.Feed(packet(pk{out: true, kind: 2, seq: 4}), at(101))
	if tr.Feed(packet(pk{kind: 3, seq: 4, cid: 2}), at(101.06)) != nil {
		t.Fatal("other client id paired")
	}
	e := tr.Feed(packet(pk{kind: 3, seq: 5}), at(101.05))
	if e == nil || e.Baseline != nil {
		t.Fatal("unmatched ack must detect without a round trip")
	}
}

func TestRestartAckVerifiesASwitch(t *testing.T) {
	tr := NewTracker()
	tr.Feed(packet(pk{out: true, seq: 3}), at(100))
	tr.Feed(packet(pk{out: true, kind: 2, seq: 4}), at(101))
	e := tr.Feed(packet(pk{kind: 3, seq: 4}), at(101.06))
	tr.Feed(packet(pk{out: true, kind: 5, seq: 6, restart: true, cookie: 12}), at(110))
	if tr.Feed(packet(pk{kind: 3, seq: 6}), at(110.05)) != nil {
		t.Fatal("restart started a new pass")
	}
	if s := tr.Latest(e.Key, at(109)); s == nil || s.RTT == nil || math.Abs(*s.RTT-50) > 0.01 {
		t.Fatalf("latest %+v", s)
	}
	if tr.Latest(e.Key, at(111)) != nil {
		t.Fatal("old restart reused")
	}
	tr.Feed(packet(pk{out: true, kind: 5, seq: 7, restart: true}), at(120))
	tr.Feed(packet(pk{out: true, kind: 5, seq: 7, restart: true}), at(120.2))
	tr.Feed(packet(pk{kind: 3, seq: 7}), at(120.25))
	if s := tr.Latest(e.Key, at(119)); s == nil || s.RTT != nil {
		t.Fatal("ambiguous restart must confirm the switch without a fake round trip")
	}
}

func TestDecodeRejectsFragmentsAndPrivateServers(t *testing.T) {
	ip := netx.Datagram(client, server, 51832, 7222, payload(pk{out: true}), 1)
	frag := append([]byte(nil), ip...)
	frag[6] = 0x20
	if _, ok := Decode(frag); ok {
		t.Fatal("fragment accepted")
	}
	lan := netx.Datagram(client, netip.MustParseAddr("192.168.1.1"), 51832, 7222, payload(pk{out: true}), 1)
	if _, ok := Decode(lan); ok {
		t.Fatal("LAN server accepted")
	}
	cut, ok := Decode(ip[:60])
	if !ok || cut.Complete {
		t.Fatal("snap-length cut should still classify, as incomplete")
	}
}
