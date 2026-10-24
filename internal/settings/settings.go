// Package settings holds the dashboard controls shared by every device.
package settings

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/demyaha/brutter/internal/config"
)

const (
	CS       = "cs2"
	Valorant = "valorant"
)

type Value struct {
	Enabled    bool           `json:"enabled"`
	Games      []string       `json:"games"`
	PortCounts map[string]int `json:"port_counts"`
	Force      bool           `json:"force"`
}

func defaults() Value {
	return Value{Enabled: true, Games: []string{CS, Valorant},
		PortCounts: map[string]int{CS: 20, Valorant: 50}}
}

func (v *Value) validate() error {
	games := map[string]bool{}
	for _, g := range v.Games {
		if g != CS && g != Valorant {
			return errors.New("invalid game selection")
		}
		games[g] = true
	}
	// Never nil: an empty selection must reach the dashboard as [], not null.
	v.Games = []string{}
	for g := range games {
		v.Games = append(v.Games, g)
	}
	sort.Strings(v.Games)
	if len(v.PortCounts) != 2 {
		return errors.New("expected port counts for both games")
	}
	for _, g := range []string{CS, Valorant} {
		if n, ok := v.PortCounts[g]; !ok || n < 5 || n > 100 {
			return errors.New("port count must be from 5 to 100")
		}
	}
	return nil
}

// Store persists the controls; Generation counts Reset presses.
type Store struct {
	mu         sync.Mutex
	path       string
	value      Value
	generation atomic.Uint64
}

func Open(path string) *Store {
	s := &Store{path: path, value: defaults()}
	data, err := os.ReadFile(path)
	if err == nil {
		v := defaults()
		if json.Unmarshal(data, &v) != nil || v.validate() != nil {
			// A damaged file must not leave optimization running blind.
			v = defaults()
			v.Enabled, v.Games = false, []string{}
		}
		s.value = v
	}
	return s
}

func (s *Store) Get() Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.value
	v.Games = append([]string{}, v.Games...)
	v.PortCounts = map[string]int{CS: v.PortCounts[CS], Valorant: v.PortCounts[Valorant]}
	return v
}

func (s *Store) Active(game string) bool {
	v := s.Get()
	if !v.Enabled {
		return false
	}
	for _, g := range v.Games {
		if g == game {
			return true
		}
	}
	return false
}

func (s *Store) Force() bool { return s.Get().Force }

func (s *Store) Count(game string) int { return s.Get().PortCounts[game] }

// Update applies a partial change: fields absent from the JSON keep their value.
func (s *Store) Update(raw []byte) (Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.value
	v.Games = append([]string{}, v.Games...)
	v.PortCounts = map[string]int{CS: v.PortCounts[CS], Valorant: v.PortCounts[Valorant]}
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		return Value{}, err
	}
	if err := v.validate(); err != nil {
		return Value{}, err
	}
	data, _ := json.Marshal(v)
	if err := config.WriteFile(s.path, data); err != nil {
		return Value{}, err
	}
	s.value = v
	return v, nil
}

// Reset asks every worker to clear its results.
func (s *Store) Reset() { s.generation.Add(1) }

func (s *Store) Generation() uint64 { return s.generation.Load() }
