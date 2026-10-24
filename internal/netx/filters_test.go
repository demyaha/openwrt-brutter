package netx

import (
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

func run(t *testing.T, prog []bpf.Instruction, packet []byte) bool {
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	n, err := vm.Run(packet)
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestServerQueryFilter(t *testing.T) {
	server := netip.MustParseAddr("203.0.113.7")
	public := netip.MustParseAddr("198.51.100.4")
	other := netip.MustParseAddr("203.0.113.8")
	query := []byte("\xff\xff\xff\xffTSource Engine Query\x00")
	cases := []struct {
		name string
		ip   []byte
		want bool
	}{
		{"reply", Datagram(server, public, 27015, 40000, []byte("\xff\xff\xff\xffI..."), 1), true},
		{"request", Datagram(public, server, 40000, 27015, query, 1), true},
		{"gameplay", Datagram(server, public, 27015, 40000, []byte{1, 2, 3, 4, 5}, 1), false},
		{"other server", Datagram(other, public, 27015, 40000, query, 1), false},
	}
	for _, c := range cases {
		if got := run(t, ServerQueryFilter(server), c.ip); got != c.want {
			t.Errorf("%s: %v want %v", c.name, got, c.want)
		}
	}
}

func TestHostPairFilter(t *testing.T) {
	a, b := netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("203.0.113.7")
	eth := func(ip []byte) []byte { return append([]byte{12: 0x08, 13: 0x00}, ip...) }
	if !run(t, HostPairFilter(a, b, 128), eth(Datagram(a, b, 1, 2, []byte("x"), 1))) {
		t.Error("pair rejected")
	}
	if run(t, HostPairFilter(a, b, 128), eth(Datagram(b, a, 2, 1, []byte("x"), 1))) {
		t.Error("reverse accepted")
	}
}
