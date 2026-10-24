//go:build !linux

package netx

import (
	"errors"
	"net/netip"
)

// Conntrack needs Linux netlink; elsewhere it only lets the code build.
type Conntrack struct{}

var errLinux = errors.New("conntrack requires Linux")

func (c *Conntrack) Flows() ([]Flow, error)                   { return nil, errLinux }
func (c *Conntrack) Delete(Flow) error                        { return errLinux }
func (c *Conntrack) DeleteLocal(netip.Addr, uint16, Endpoint) {}
func (c *Conntrack) Lookup(Tuple) (Flow, bool, error)         { return Flow{}, false, errLinux }
