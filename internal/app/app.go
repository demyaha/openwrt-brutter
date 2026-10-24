// Package app runs one CS and one Valorant worker per selected device.
package app

import (
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/demyaha/brutter/internal/activity"
	"github.com/demyaha/brutter/internal/config"
	"github.com/demyaha/brutter/internal/cs"
	"github.com/demyaha/brutter/internal/devices"
	"github.com/demyaha/brutter/internal/firewall"
	"github.com/demyaha/brutter/internal/netx"
	"github.com/demyaha/brutter/internal/settings"
	"github.com/demyaha/brutter/internal/valorant"
)

type device struct {
	cs       *cs.Worker
	valorant *valorant.Worker
}

type App struct {
	Config   *config.Config
	Settings *settings.Store
	Devices  *devices.Lister
	table    *netx.Conntrack
	board    *activity.Board
	capture  *valorant.Capture
	captureE error
	mu       sync.Mutex
	clients  []netip.Addr
	workers  map[netip.Addr]*device
	boot     bool
	fw       *firewall.Include
	fwMu     sync.Mutex // one firewall sync at a time
	fwErr    string
}

func New(c *config.Config) *App {
	return &App{
		Config:   c,
		Settings: settings.Open(filepath.Join(c.StateDir, "ping-brutter-settings.json")),
		Devices: &devices.Lister{LAN: c.LAN, Listen: c.Listen,
			Leases: "/tmp/dhcp.leases", ARP: "/proc/net/arp"},
		table:   &netx.Conntrack{},
		board:   activity.New(),
		workers: map[netip.Addr]*device{},
		fw:      firewall.Default(),
	}
}

// syncFirewall keeps the offload exclusion in step with the selected devices.
func (a *App) syncFirewall() {
	a.fwMu.Lock()
	defer a.fwMu.Unlock()
	msg := ""
	if err := a.fw.Sync(a.Config.LAN, a.Clients()); err != nil {
		msg = err.Error()
		log.Printf("offload exclusion: %v", err)
	}
	a.mu.Lock()
	a.fwErr = msg
	a.mu.Unlock()
}

// FirewallError explains why the offload exclusion could not be applied, if so.
func (a *App) FirewallError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fwErr
}

// Start cleans up after an earlier process and starts every device.
func (a *App) Start() error {
	if _, err := a.table.Flows(); err != nil {
		return err
	}
	valorant.CleanupSwitches()
	marker := filepath.Join(a.Config.RAMDir, "brutter-booted")
	if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
		// RAM is empty only after a reboot: then saved CS servers are checked once.
		a.boot = true
		_ = os.WriteFile(marker, nil, 0o600)
	}
	a.capture, a.captureE = valorant.OpenCapture(a.Config.LAN)
	if a.captureE != nil {
		log.Printf("valorant handshake capture unavailable: %v", a.captureE)
	}
	var clients []netip.Addr
	for _, s := range a.Config.Clients {
		clients = append(clients, netip.MustParseAddr(s))
	}
	a.mu.Lock()
	for _, c := range clients {
		a.start(c)
	}
	a.clients = clients
	a.boot = false
	a.mu.Unlock()
	go a.syncFirewall()
	return nil
}

func (a *App) start(client netip.Addr) {
	key := config.Key(client)
	store := cs.OpenStore(filepath.Join(a.Config.StateDir, "ping-brutter-cs2-history-"+key+".json"), time.Now)
	d := &device{}
	d.cs = cs.NewWorker(cs.Env{
		Client: client, WAN: a.Config.WAN, LAN: a.Config.LAN, Table: a.table,
		Settings: a.Settings, Board: a.board, Store: store,
		Pins: &cs.Pins{Client: client, Table: cs.PinPrefix + key, WAN: a.Config.WAN},
		Reconnect: &cs.Reconnect{Client: client, Table: cs.ReconnectPrefix + key,
			LAN: a.Config.LAN, WAN: a.Config.WAN, Flows: a.table},
		Rejoin: &cs.Rejoin{Client: client, Table: cs.RejoinPrefix + key, LAN: a.Config.LAN,
			WAN: a.Config.WAN, Flows: a.table},
		Others: func() map[uint16]bool { return a.others(client) },
		Boot:   a.boot,
	})
	d.valorant = valorant.NewWorker(valorant.Env{
		Client: client, WAN: a.Config.WAN, LAN: a.Config.LAN, Table: a.table,
		Settings: a.Settings, Board: a.board, Capture: a.capture,
	})
	a.workers[client] = d
	go d.cs.Run()
	go d.valorant.Run()
	log.Printf("device %s started", client)
}

func (a *App) others(client netip.Addr) map[uint16]bool {
	a.mu.Lock()
	var workers []*cs.Worker
	for c, d := range a.workers {
		if c != client {
			workers = append(workers, d.cs)
		}
	}
	a.mu.Unlock()
	out := map[uint16]bool{}
	for _, w := range workers {
		for p := range w.Armed() {
			out[p] = true
		}
	}
	return out
}

// Clients are the selected devices, in order.
func (a *App) Clients() []netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]netip.Addr(nil), a.clients...)
}

// Workers returns a device's workers.
func (a *App) Workers(client netip.Addr) (*cs.Worker, *valorant.Worker, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.workers[client]
	if !ok {
		return nil, nil, false
	}
	return d.cs, d.valorant, true
}

// CaptureError explains why Valorant joins cannot be seen, if so.
func (a *App) CaptureError() string {
	if a.captureE != nil {
		return a.captureE.Error()
	}
	if a.capture != nil {
		if err := a.capture.Failed(); err != nil {
			return err.Error()
		}
	}
	return ""
}

// SetClients changes the selected devices without restarting the others.
func (a *App) SetClients(list []string) error {
	known := map[string]bool{}
	for _, d := range a.Devices.List(a.Clients()) {
		known[d.IP] = true
	}
	var clients []netip.Addr
	for _, s := range list {
		if !known[s] {
			return errors.New("select a known LAN device")
		}
		clients = append(clients, netip.MustParseAddr(s))
	}
	next := *a.Config
	next.Clients = list
	if err := next.Validate(); err != nil {
		return err
	}
	if err := next.Save(); err != nil {
		return err
	}
	a.mu.Lock()
	*a.Config = next
	selected := map[netip.Addr]bool{}
	for _, c := range clients {
		selected[c] = true
	}
	var stopping []*device
	for c, d := range a.workers {
		if !selected[c] {
			stopping = append(stopping, d)
			delete(a.workers, c)
		}
	}
	for _, c := range clients {
		if a.workers[c] == nil {
			a.start(c)
		}
	}
	a.clients = clients
	a.mu.Unlock()
	go a.syncFirewall()
	for _, d := range stopping {
		d.cs.Stop()
		d.valorant.Stop()
	}
	return nil
}

// Stop removes every rule Brutter added.
func (a *App) Stop() {
	a.mu.Lock()
	workers := a.workers
	a.workers = map[netip.Addr]*device{}
	a.mu.Unlock()
	var wg sync.WaitGroup
	for _, d := range workers {
		wg.Add(2)
		go func(d *device) { defer wg.Done(); d.cs.Stop() }(d)
		go func(d *device) { defer wg.Done(); d.valorant.Stop() }(d)
	}
	wg.Wait()
	if a.capture != nil {
		a.capture.Close()
	}
	valorant.CleanupSwitches()
}
