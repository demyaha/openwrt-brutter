// Package firewall keeps the gaming devices' UDP out of flow offload. Offloaded
// packets skip the netfilter forward hook, where Brutter holds a reconnect, and
// leave conntrack entries without the states a port switch waits for.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Name is the firewall4 include Brutter owns in /etc/nftables.d.
const Name = "20-brutter.nft"

// Earlier hand-made includes with the same purpose; Sync replaces them.
var legacy = []string{"20-brutter-valorant-offload.nft", "20-brutter-game-offload.nft"}

// Include manages the file. FW4 runs firewall4; nil means the system command.
type Include struct {
	Dir string
	FW4 func(args ...string) ([]byte, error)
}

// Default is the include on an OpenWrt router.
func Default() *Include { return &Include{Dir: "/etc/nftables.d"} }

// Render returns the include for clients, or "" when there are none.
func Render(lan string, clients []netip.Addr) string {
	if len(clients) == 0 {
		return ""
	}
	addrs := make([]string, len(clients))
	for i, c := range clients {
		addrs[i] = c.String()
	}
	set := strings.Join(addrs, ", ")
	return fmt.Sprintf(`# Managed by Brutter: rewritten when the gaming devices change.
# Their UDP stays out of flow offload; their TCP is still offloaded.
chain forward {
	type filter hook forward priority filter;
	meta l4proto udp ct original ip saddr { %[2]s } ct state established counter accept comment "Brutter: game UDP without offload"
	iifname %[1]q ip saddr { %[2]s } meta l4proto udp counter jump forward_lan comment "Brutter: game UDP follows the LAN policy"
}
`, lan, set)
}

func (in *Include) fw4(args ...string) ([]byte, error) {
	if in.FW4 != nil {
		return in.FW4(args...)
	}
	return exec.Command("fw4", args...).CombinedOutput()
}

// Sync writes the include for clients and reloads the firewall when anything
// changed. Without firewall4 it does nothing; a ruleset firewall4 rejects is
// rolled back before any reload.
func (in *Include) Sync(lan string, clients []netip.Addr) error {
	if _, err := os.Stat(in.Dir); err != nil {
		return nil
	}
	if in.FW4 == nil {
		if _, err := exec.LookPath("fw4"); err != nil {
			return nil
		}
	}
	path := filepath.Join(in.Dir, Name)
	want := Render(lan, clients)
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stale := map[string][]byte{}
	for _, name := range legacy {
		if data, err := os.ReadFile(filepath.Join(in.Dir, name)); err == nil {
			stale[name] = data
		}
	}
	if string(old) == want && len(stale) == 0 {
		return nil
	}
	restore := func() {
		if old != nil {
			_ = os.WriteFile(path, old, 0o644)
		} else {
			_ = os.Remove(path)
		}
		for name, data := range stale {
			_ = os.WriteFile(filepath.Join(in.Dir, name), data, 0o644)
		}
	}
	if want == "" {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else {
		err = os.WriteFile(path, []byte(want), 0o644)
	}
	if err != nil {
		restore()
		return err
	}
	for name := range stale {
		_ = os.Remove(filepath.Join(in.Dir, name))
	}
	if out, err := in.fw4("check"); err != nil {
		restore()
		return fmt.Errorf("firewall4 rejected the offload exclusion: %s", strings.TrimSpace(string(out)))
	}
	if out, err := in.fw4("reload"); err != nil {
		return fmt.Errorf("firewall4 reload: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
