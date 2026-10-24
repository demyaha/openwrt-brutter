package valorant

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// slowPorts is shared between a test and its fake server goroutine.
type slowPorts struct {
	mu    sync.Mutex
	ports map[int]bool
}

func (s *slowPorts) add(port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ports == nil {
		s.ports = map[int]bool{}
	}
	s.ports[port] = true
}

func (s *slowPorts) has(port int) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ports[port]
}

// fakeServer answers Initials with Challenges, slower for some source ports.
func fakeServer(t *testing.T, slow *slowPorts) netip.AddrPort {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			h, ok := ParseHeader(buf[:n], true, n)
			if !ok || h.Kind != KindInitial {
				continue
			}
			reply := payload(pk{kind: KindChallenge, seq: h.Seq, cid: h.CID})
			delay := 5 * time.Millisecond
			if slow.has(from.Port) {
				delay = 40 * time.Millisecond
			}
			time.AfterFunc(delay, func() { conn.WriteToUDP(reply, from) })
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestProberFindsTheFastPortAndIgnoresStaleReplies(t *testing.T) {
	slow := &slowPorts{}
	server := fakeServer(t, slow)
	p, err := NewProber(netip.MustParseAddr("127.0.0.1"), server, payload(pk{out: true}), func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(nil)
	if err := p.Allocate(8, nil); err != nil {
		t.Fatal(err)
	}
	var fast uint16
	for port := range p.sockets {
		if fast == 0 {
			fast = port
		} else {
			slow.add(int(port))
		}
	}
	started := time.Now()
	calls := 0
	probes, best, err := p.Measure(func(done, total int) { calls++ })
	if err != nil {
		t.Fatal(err)
	}
	if best == nil || best.Port != fast {
		t.Fatalf("best %+v, want port %d", best, fast)
	}
	if *best.RTT > 20 {
		t.Fatalf("fast port measured %.1f ms", *best.RTT)
	}
	if len(probes) != 8 || calls == 0 {
		t.Fatalf("probes %d calls %d", len(probes), calls)
	}
	// 8 ports x 2 rounds + 5 finalists x 4 = 36 requests at 20/s.
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("scan took %v", elapsed)
	}
}

func TestProberStopsWhenCancelled(t *testing.T) {
	server := fakeServer(t, nil)
	stop := false
	p, _ := NewProber(netip.MustParseAddr("127.0.0.1"), server, payload(pk{out: true}), func() bool { return stop })
	defer p.Close(nil)
	p.Allocate(4, nil)
	stop = true
	if _, _, err := p.Measure(func(int, int) {}); err != ErrCancelled {
		t.Fatalf("err %v", err)
	}
}

func TestProberMeasuresOneChosenPort(t *testing.T) {
	server := fakeServer(t, nil)
	free, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(free.LocalAddr().(*net.UDPAddr).Port)
	free.Close()
	p, err := NewProber(netip.MustParseAddr("127.0.0.1"), server, payload(pk{out: true}), func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(nil)
	probe, err := p.MeasureOne(port, 6)
	if err != nil {
		t.Fatal(err)
	}
	if probe.Port != port || len(probe.Samples) != 6 || probe.RTT == nil || *probe.RTT > 20 {
		t.Fatalf("probe %+v", probe)
	}
	for _, s := range probe.Samples {
		if s == nil {
			t.Fatal("a request went unanswered")
		}
	}
}

func TestProberRefusesAuthenticatedTemplates(t *testing.T) {
	if _, err := NewProber(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddrPort("127.0.0.1:7000"),
		payload(pk{out: true, cookie: 7}), func() bool { return false }); err == nil {
		t.Fatal("cookie template accepted")
	}
}
