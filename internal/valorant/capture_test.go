package valorant

import (
	"testing"

	"golang.org/x/net/bpf"

	"github.com/demyaha/brutter/internal/netx"
)

func frame(ip []byte) []byte {
	f := make([]byte, 14, 14+len(ip))
	f[12], f[13] = 0x08, 0x00
	return append(f, ip...)
}

func TestHandshakeFilterMatchesTheGoPredicate(t *testing.T) {
	vm, err := bpf.NewVM(HandshakeFilter())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ip   []byte
		want bool
	}{
		{"initial out", netx.Datagram(client, server, 51832, 7222, payload(pk{out: true}), 1), true},
		{"challenge in", netx.Datagram(server, client, 7222, 51832, payload(pk{kind: 1}), 1), true},
		{"ack in", netx.Datagram(server, client, 8000, 51832, payload(pk{kind: 3}), 1), true},
		{"other port", netx.Datagram(client, server, 51832, 8001, payload(pk{out: true}), 1), false},
		{"gameplay", netx.Datagram(client, server, 51832, 7222, make([]byte, 120), 1), false},
		{"version 5", netx.Datagram(client, server, 51832, 7222, payload(pk{out: true, version: 5}), 1), false},
	}
	for _, c := range cases {
		n, err := vm.Run(frame(c.ip))
		if err != nil {
			t.Fatal(err)
		}
		if (n > 0) != c.want {
			t.Errorf("%s: filter %v, want %v", c.name, n > 0, c.want)
		}
		if _, ok := Decode(c.ip); ok != c.want && c.name != "version 5" {
			t.Errorf("%s: decode %v, want %v", c.name, ok, c.want)
		}
	}
}
