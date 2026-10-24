// Package cs keeps each saved CS server pinned to its fastest port: a server
// is measured once, and every later join leaves from the chosen port.
package cs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/demyaha/brutter/internal/netx"
)

const (
	AppID = 730
	// Valve servers answer about three queries per second per address on average.
	pace      = 200 * time.Millisecond
	a2sWait   = 800 * time.Millisecond
	maxProbed = 100
)

var Query = []byte("\xff\xff\xff\xffTSource Engine Query\x00")

// Info is what an A2S_INFO reply says about a server.
type Info struct {
	Name, Map           string
	AppID               uint16
	Players, MaxPlayers int
}

const maxName = 64

// Bytes 0x80-0xBF of Windows-1251; 0xC0-0xFF are А-я in order.
var cp1251 = []rune("ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—\uFFFD™љ›њќћџ\u00A0ЎўЈ¤Ґ¦§Ё©Є«¬\u00AD®Ї°±Ііґµ¶·ё№є»јЅѕї")

// decode reads UTF-8, which servers send today; older Russian servers send
// Windows-1251, which is not valid UTF-8.
func decode(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	r := make([]rune, len(b))
	for i, c := range b {
		switch {
		case c < 0x80:
			r[i] = rune(c)
		case c < 0xc0:
			r[i] = cp1251[c-0x80]
		default:
			r[i] = 0x410 + rune(c-0xc0)
		}
	}
	return string(r)
}

// clean keeps a server-chosen string printable and short.
func clean(b []byte) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r == '\t', r == '\n', r == '\r':
			return ' '
		case r < 0x20, r >= 0x7f && r < 0xa0, r == utf8.RuneError:
			return -1 // controls (CS:GO colour codes among them)
		case r == 0x200b, r == 0x200e, r == 0x200f, r == 0xfeff,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return -1 // invisible spaces and bidirectional overrides
		}
		return r
	}, decode(b))
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= maxName {
		return s
	}
	r = r[:maxName]
	// Do not leave half an emoji: a dangling joiner, selector or skin tone,
	// or one of the two letters of a flag.
	for len(r) > 0 && (r[len(r)-1] == 0x200d || r[len(r)-1] == 0xfe0f ||
		(r[len(r)-1] >= 0x1f3fb && r[len(r)-1] <= 0x1f3ff)) {
		r = r[:len(r)-1]
	}
	flags := 0
	for i := len(r) - 1; i >= 0 && r[i] >= 0x1f1e6 && r[i] <= 0x1f1ff; i-- {
		flags++
	}
	if flags%2 == 1 {
		r = r[:len(r)-1]
	}
	return strings.TrimSpace(string(r)) + "…"
}

// ParseInfo validates an A2S_INFO reply.
func ParseInfo(p []byte) (Info, error) {
	if len(p) < 6 || !bytes.HasPrefix(p, []byte("\xff\xff\xff\xffI")) {
		return Info{}, errors.New("unsupported A2S response")
	}
	off := 6
	var fields [4][]byte // name, map, folder, game
	for i := range fields {
		end := bytes.IndexByte(p[off:], 0)
		if end < 0 {
			return Info{}, errors.New("truncated A2S string")
		}
		fields[i] = p[off : off+end]
		off += end + 1
	}
	if len(p) < off+9 {
		return Info{}, errors.New("truncated A2S fields")
	}
	// Require the terminating version string, not just a forged prefix.
	if bytes.IndexByte(p[off+9:], 0) < 0 {
		return Info{}, errors.New("truncated A2S version")
	}
	return Info{Name: clean(fields[0]), Map: clean(fields[1]), AppID: binary.LittleEndian.Uint16(p[off:]),
		Players: int(p[off+2]), MaxPlayers: int(p[off+3])}, nil
}

func exchange(s *netx.Socket, payload []byte) ([]byte, float64, error) {
	sent, err := s.Send(payload)
	if err != nil {
		return nil, 0, err
	}
	data, at, err := s.Receive(sent.Add(a2sWait))
	if err != nil {
		return nil, 0, err
	}
	return append([]byte(nil), data...), float64(at.Sub(sent).Microseconds()) / 1000, nil
}

// query asks once, answering an A2S challenge if the server sends one.
func query(s *netx.Socket, challenge []byte) (float64, []byte, Info, error) {
	data, rtt, err := exchange(s, append(append([]byte(nil), Query...), challenge...))
	if err != nil {
		return 0, nil, Info{}, err
	}
	if bytes.HasPrefix(data, []byte("\xff\xff\xff\xffA")) {
		if len(data) != 9 {
			return 0, nil, Info{}, errors.New("invalid A2S challenge")
		}
		challenge = data[5:9]
		if data, rtt, err = exchange(s, append(append([]byte(nil), Query...), challenge...)); err != nil {
			return 0, nil, Info{}, err
		}
	}
	info, err := ParseInfo(data)
	if err != nil {
		return 0, nil, Info{}, err
	}
	if info.AppID != AppID {
		return 0, nil, Info{}, errors.New("not a CS server")
	}
	return rtt, challenge, info, nil
}

// Probe is one source port's A2S result.
type Probe struct {
	Port    uint16    `json:"port"`
	RTT     *float64  `json:"rtt_ms"`
	Samples []float64 `json:"samples_ms"`
	Error   string    `json:"error,omitempty"`
	Info    *Info     `json:"-"`
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// RandomPorts picks count free high ports.
func RandomPorts(count int, busy map[uint16]bool) []uint16 {
	var out []uint16
	seen := map[uint16]bool{}
	for tries := 0; len(out) < count && tries < count*50+50; tries++ {
		p := uint16(20000 + rand.IntN(44001))
		if !busy[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// ProbePorts measures A2S from each source port; any doubt discards a port.
func ProbePorts(table netx.Table, local func(netip.Addr, uint16, netx.Endpoint), public netip.Addr,
	ep netx.Endpoint, ports []uint16, rounds int, cancel func() error, progress func()) ([]Probe, error) {
	if rounds < 1 || rounds > 6 || len(ports) == 0 || len(ports) > maxProbed {
		return nil, errors.New("probe budget exceeded")
	}
	flows, err := table.Flows()
	if err != nil {
		return nil, err
	}
	occupied := netx.Occupied(flows, public, ep)
	type rec struct {
		sock      *netx.Socket
		samples   []float64
		challenge []byte
		err       string
		sent      bool
		info      *Info
	}
	recs := make([]*rec, len(ports))
	defer func() {
		for i, r := range recs {
			if r.sock != nil {
				r.sock.Close()
			}
			if r.sent && local != nil {
				// Only the router's own probe, never the device's game tuple.
				local(public, ports[i], ep)
			}
		}
	}()
	server := netip.AddrPortFrom(ep.Server, ep.Port)
	for i, port := range ports {
		recs[i] = &rec{}
		if occupied[port] {
			recs[i].err = "port is in use toward this server"
			continue
		}
		if recs[i].sock, err = netx.Dial(netip.AddrPortFrom(public, port), server); err != nil {
			recs[i].err = err.Error()
		}
	}
	for round := 0; round < rounds; round++ {
		for _, r := range recs {
			if err := cancel(); err != nil {
				return nil, err
			}
			if r.err != "" {
				continue
			}
			started := time.Now()
			r.sent = true
			rtt, challenge, info, err := query(r.sock, r.challenge)
			if err != nil {
				// Never reuse a timed-out socket: a late reply could pass for the
				// next request's low round trip.
				r.err = err.Error()
			} else {
				r.challenge = challenge
				r.samples = append(r.samples, rtt)
				r.info = &info
			}
			progress()
			time.Sleep(pace - time.Since(started))
		}
	}
	if flows, err = table.Flows(); err == nil {
		for i, r := range recs {
			if r.err != "" || !r.sent {
				continue
			}
			n := 0
			for _, f := range flows {
				if f.Client == public && f.Server == ep.Server && f.DPort == ep.Port && f.SPort == ports[i] {
					n++
					if f.External != ports[i] {
						n = 99
					}
				}
			}
			if n != 1 {
				r.err = "probe source port was remapped"
			}
		}
	}
	out := make([]Probe, len(ports))
	for i, r := range recs {
		out[i] = Probe{Port: ports[i], Samples: r.samples, Error: r.err, Info: r.info}
		if r.err == "" && len(r.samples) == rounds {
			m := median(r.samples)
			out[i].RTT = &m
		}
	}
	return out, nil
}
