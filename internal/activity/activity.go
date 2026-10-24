// Package activity keeps one game per device: while a match runs, the other
// game's worker on the same device stands by.
package activity

import (
	"net/netip"
	"sync"
	"time"
)

// A claim lapses if its worker stops refreshing it.
const lease = 15 * time.Second

type owner struct {
	game string
	at   time.Time
}

type Board struct {
	mu     sync.Mutex
	owners map[netip.Addr]owner
	now    func() time.Time
}

func New() *Board { return &Board{owners: map[netip.Addr]owner{}, now: time.Now} }

// Claim takes or refreshes the device for game; false if the other game holds it.
func (b *Board) Claim(client netip.Addr, game string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.owners[client]
	if ok && o.game != game && b.now().Sub(o.at) < lease {
		return false
	}
	b.owners[client] = owner{game, b.now()}
	return true
}

// Release frees the device if game holds it.
func (b *Board) Release(client netip.Addr, game string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o, ok := b.owners[client]; ok && o.game == game {
		delete(b.owners, client)
	}
}

// Other names the other game while it holds the device, or "".
func (b *Board) Other(client netip.Addr, game string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.owners[client]
	if !ok || o.game == game || b.now().Sub(o.at) >= lease {
		return ""
	}
	return o.game
}
