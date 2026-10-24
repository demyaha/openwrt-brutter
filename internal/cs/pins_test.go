package cs

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/demyaha/brutter/internal/netx"
)

// Adding a set element makes nft load every set on the router (about a second
// of CPU next to a large set), so the rules must not use one.
func TestRulesNameTheDeviceWithoutASet(t *testing.T) {
	client := netip.MustParseAddr("192.168.1.100")
	ep := netx.Endpoint{Server: netip.MustParseAddr("203.0.113.20"), Port: 27015}
	pin := pinRule("brutter_cs_x", "pppoe-wan", client, ep, 40000)
	r := &Reconnect{Client: client, Table: "brutter_csrc_x", LAN: "br-lan", WAN: "pppoe-wan"}
	re := r.batch(netx.Flow{Client: client, Server: ep.Server, SPort: 51000, DPort: 27015})
	for name, batch := range map[string]string{"pin": pin, "reconnect": re} {
		if strings.Contains(batch, "@lease") || strings.Contains(batch, "add element") || strings.Contains(batch, "add set") {
			t.Fatalf("%s rule still uses a set:\n%s", name, batch)
		}
		if !strings.Contains(batch, "ip saddr 192.168.1.100") {
			t.Fatalf("%s rule does not name the device:\n%s", name, batch)
		}
	}
}
