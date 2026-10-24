// Package devices lists LAN devices from DHCP leases and the neighbor table.
package devices

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Device struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type Lister struct {
	LAN, Listen string
	Leases      string // /tmp/dhcp.leases
	ARP         string // /proc/net/arp
	mu          sync.Mutex
	cached      []Device
	at          time.Time
}

func (l *Lister) network() netip.Prefix {
	listen := netip.MustParseAddr(l.Listen)
	if iface, err := net.InterfaceByName(l.LAN); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					if p, err := netip.ParsePrefix(n.String()); err == nil && p.Contains(listen) {
						return p.Masked()
					}
				}
			}
		}
	}
	return netip.PrefixFrom(listen, 24).Masked()
}

// List returns known devices, cached for 30 seconds; selected are always included.
func (l *Lister) List(selected []netip.Addr) []Device {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cached == nil || time.Since(l.at) > 30*time.Second {
		l.cached, l.at = l.read(), time.Now()
	}
	out := append([]Device(nil), l.cached...)
	for _, s := range selected {
		found := false
		for _, d := range out {
			found = found || d.IP == s.String()
		}
		if !found {
			out = append(out, Device{s.String(), s.String()})
		}
	}
	return out
}

func (l *Lister) read() []Device {
	network := l.network()
	items := map[string]*Device{}
	add := func(ip, name string) {
		a, err := netip.ParseAddr(ip)
		if err != nil || !network.Contains(a) || ip == l.Listen {
			return
		}
		d := items[ip]
		if d == nil {
			d = &Device{IP: ip, Name: ip}
			items[ip] = d
		}
		if name != "" && name != "*" {
			if len(name) > 63 {
				name = name[:63]
			}
			d.Name = name
		}
	}
	if f, err := os.Open(l.Leases); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if fields := strings.Fields(s.Text()); len(fields) >= 4 {
				add(fields[2], fields[3])
			}
		}
		f.Close()
	}
	if f, err := os.Open(l.ARP); err == nil {
		s := bufio.NewScanner(f)
		s.Scan()
		for s.Scan() {
			// IP address, HW type, Flags, HW address, Mask, Device
			if fields := strings.Fields(s.Text()); len(fields) >= 6 && fields[5] == l.LAN && fields[2] != "0x0" {
				add(fields[0], "")
			}
		}
		f.Close()
	}
	out := make([]Device, 0, len(items))
	for _, d := range items {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].IP < out[j].IP
	})
	return out
}
