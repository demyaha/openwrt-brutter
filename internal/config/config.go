// Package config reads the installation settings in /etc/ping-brutter.json.
package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const DefaultPath = "/etc/ping-brutter.json"

// Config is the installation. An empty listen address or WAN interface is
// found at start: the LAN interface's address and the default route's interface.
type Config struct {
	Clients    []string `json:"clients"`
	Listen     string   `json:"listen,omitempty"`
	Port       int      `json:"port"`
	WAN        string   `json:"wan_interface,omitempty"`
	LAN        string   `json:"lan_interface"`
	StateDir   string   `json:"state_dir"`
	RAMDir     string   `json:"ram_dir"`
	WANNetwork string   `json:"wan_network,omitempty"` // kept for older files
	Client     string   `json:"client,omitempty"`      // kept for older files
	path       string
	autoListen bool
	autoWAN    bool
}

var iface = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func Defaults() Config {
	return Config{Clients: []string{}, Port: 1337, LAN: "br-lan", StateDir: "/root", RAMDir: "/tmp"}
}

// LAN reports a usable local device address.
func LAN(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.IsMulticast() || a.IsUnspecified() ||
		!(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
		return netip.Addr{}, fmt.Errorf("%q is not a local IPv4 address", s)
	}
	return a, nil
}

func (c *Config) Validate() error {
	if len(c.Clients) == 0 && c.Client != "" {
		c.Clients = []string{c.Client}
	}
	if c.Clients == nil {
		c.Clients = []string{}
	}
	seen := map[string]bool{}
	for _, s := range c.Clients {
		if _, err := LAN(s); err != nil {
			return err
		}
		if seen[s] {
			return errors.New("select different gaming devices")
		}
		seen[s] = true
	}
	c.Client = ""
	if c.Listen != "" {
		if _, err := LAN(c.Listen); err != nil {
			return err
		}
	}
	if c.Port < 1024 || c.Port > 65535 {
		return errors.New("invalid HTTP port")
	}
	if (c.WAN != "" && !iface.MatchString(c.WAN)) || !iface.MatchString(c.LAN) {
		return errors.New("invalid interface name")
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.RAMDir) {
		return errors.New("expected absolute state paths")
	}
	return nil
}

// Load reads and validates a configuration file; a missing file gives defaults.
func Load(path string) (*Config, error) {
	c := Defaults()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		decoder := json.NewDecoder(bytesReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&c); err != nil {
			return nil, fmt.Errorf("configuration: %w", err)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.path = path
	return &c, nil
}

// Resolve fills in the automatic listen address and WAN interface. It fails
// while the network is not up yet, as during boot before PPPoE connects.
func (c *Config) Resolve() error {
	if c.Listen == "" || c.autoListen {
		a, err := interfaceAddr(c.LAN)
		if err != nil {
			return err
		}
		c.Listen, c.autoListen = a.String(), true
	}
	if c.WAN == "" || c.autoWAN {
		f, err := os.Open("/proc/net/route")
		if err != nil {
			return err
		}
		defer f.Close()
		name, err := defaultRoute(f)
		if err != nil {
			return err
		}
		c.WAN, c.autoWAN = name, true
	}
	return nil
}

func interfaceAddr(name string) (netip.Addr, error) {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := link.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok {
				if _, err := LAN(ip.String()); err == nil {
					return ip, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no local IPv4 address", name)
}

// defaultRoute returns the interface of the IPv4 default route with the
// lowest metric, read from /proc/net/route.
func defaultRoute(r io.Reader) (string, error) {
	best, metric := "", -1
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&1 == 0 { // RTF_UP
			continue
		}
		m, err := strconv.Atoi(f[6])
		if err != nil || !iface.MatchString(f[0]) {
			continue
		}
		if metric < 0 || m < metric {
			best, metric = f[0], m
		}
	}
	if best == "" {
		return "", errors.New("no IPv4 default route")
	}
	return best, nil
}

// Save writes the file atomically; automatic fields stay empty in it.
func (c *Config) Save() error {
	out := *c
	if c.autoListen {
		out.Listen = ""
	}
	if c.autoWAN {
		out.WAN = ""
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(c.path, append(data, '\n'))
}

// WriteFile replaces a file atomically, owner-only.
func WriteFile(path string, data []byte) error {
	temp := path + ".new"
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

// Key is the file-name form of a device address, as older versions used.
func Key(client netip.Addr) string {
	b := client.As4()
	return fmt.Sprintf("%02x%02x%02x%02x", b[0], b[1], b[2], b[3])
}
