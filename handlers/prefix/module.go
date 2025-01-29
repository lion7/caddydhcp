// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package prefix

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bits-and-blooms/bitset"
	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv6"
	dhcpIana "github.com/insomniacslk/dhcp/iana"
	"github.com/lion7/caddydhcp/handlers"
	"github.com/lion7/caddydhcp/handlers/allocators"
	"github.com/lion7/caddydhcp/handlers/allocators/bitmap"
	"go.uber.org/zap"
)

type Module struct {
	Prefix         string         `json:"prefix"`
	AllocationSize int            `json:"allocationSize"`
	LeaseTime      caddy.Duration `json:"leaseTime,omitempty"`

	logger    *zap.Logger
	allocator allocators.Allocator
	recLock   *sync.RWMutex
	records   map[string][]record
}

type record struct {
	Prefix net.IPNet
	Expire time.Time
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.prefix",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	_, prefix, err := net.ParseCIDR(m.Prefix)
	if err != nil {
		return fmt.Errorf("invalid pool subnet: %v", err)
	}

	if m.AllocationSize < 0 || m.AllocationSize > 128 {
		return fmt.Errorf("invalid prefix length: %v", err)
	}

	// TODO: select allocators based on heuristics or user configuration
	m.allocator, err = bitmap.NewBitmapAllocator(*prefix, m.AllocationSize)
	if err != nil {
		return fmt.Errorf("could not initialize prefix allocator: %v", err)
	}

	return nil
}

func (m *Module) Handle4(_, _ handlers.DHCPv4, next func() error) error {
	// prefix does not apply to DHCPv4, so just continue the chain
	return next()
}

func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	duidOpt := req.Options.ClientID()
	duid := hex.EncodeToString(duidOpt.ToBytes())

	// A possible simple optimization here would be to be able to lock single map values
	// individually instead of the whole map, since we lock for some amount of time
	m.recLock.RLock()
	defer m.recLock.RUnlock()

	// Each request IA_PD requires an IA_PD response
	for _, iapd := range req.Options.IAPD() {
		iapdResp := &dhcpv6.OptIAPD{
			IaId: iapd.IaId,
		}

		// First figure out what prefixes the client wants
		hints := iapd.Options.Prefixes()
		if len(hints) == 0 {
			// If there are no IAPrefix hints, this is still a valid IA_PD request (just
			// unspecified) and we must attempt to allocate a prefix; so we include an empty hint
			// which is equivalent to no hint
			hints = []*dhcpv6.OptIAPrefix{{Prefix: &net.IPNet{}}}
		}

		// Bitmap to track which requests are already satisfied or not
		satisfied := bitset.New(uint(len(hints)))
		// Check if there are known leases for this DUID
		knownLeases := m.records[duid]
		// Bitmap to track which leases are already given in this exchange
		givenOut := bitset.New(uint(len(knownLeases)))

		// This is, for now, a set of heuristics, to reconcile the requests (prefix hints asked
		// by the clients) with what's on offer (existing leases for this client, plus new blocks)

		// Try to find leases that exactly match a hint, and extend them to satisfy the request
		// This is the safest heuristic, if the record matches exactly we know we aren't missing
		// assigning it to a better candidate request
		for hintIdx, h := range hints {
			for leaseIdx := range knownLeases {
				if samePrefix(h.Prefix, &knownLeases[leaseIdx].Prefix) {
					expire := time.Now().Add(time.Duration(m.LeaseTime))
					if knownLeases[leaseIdx].Expire.Before(expire) {
						knownLeases[leaseIdx].Expire = expire
					}
					satisfied.Set(uint(hintIdx))
					givenOut.Set(uint(leaseIdx))
					addPrefix(iapdResp, knownLeases[leaseIdx])
				}
			}
		}

		// Then handle the empty hints, by giving out any remaining record we
		// have already assigned to this client
		for hintIdx, h := range hints {
			if satisfied.Test(uint(hintIdx)) ||
				(h.Prefix != nil && !h.Prefix.IP.Equal(net.IPv6zero)) {
				continue
			}
			for leaseIdx, l := range knownLeases {
				if givenOut.Test(uint(leaseIdx)) {
					continue
				}

				// If a length was requested, only give out prefixes of that length
				// This is a bad heuristic depending on the allocator behavior, to be improved
				if hintPrefixLen, _ := h.Prefix.Mask.Size(); hintPrefixLen != 0 {
					leasePrefixLen, _ := l.Prefix.Mask.Size()
					if hintPrefixLen != leasePrefixLen {
						continue
					}
				}
				expire := time.Now().Add(time.Duration(m.LeaseTime))
				if knownLeases[leaseIdx].Expire.Before(expire) {
					knownLeases[leaseIdx].Expire = expire
				}
				satisfied.Set(uint(hintIdx))
				givenOut.Set(uint(leaseIdx))
				addPrefix(iapdResp, knownLeases[leaseIdx])
			}
		}

		// Now remains requests with a hint that we can't trivially satisfy, and possibly expired
		// leases that haven't been explicitly requested again.
		// A possible improvement here would be to try to widen existing leases, to satisfy wider
		// requests that contain an existing leases; and to try to break down existing leases into
		// smaller allocations, to satisfy requests for a subnet of an existing record
		// We probably don't need such complex behavior (the vast majority of requests will come
		// with an empty, or length-only hint)

		// Assign a new record to satisfy the request
		var newLeases []record
		for i, prefix := range hints {
			if satisfied.Test(uint(i)) {
				continue
			}

			if prefix.Prefix == nil {
				// XXX: replace usage of dhcp.OptIAPrefix with a better struct in this inner
				// function to avoid repeated null-pointer checks
				prefix.Prefix = &net.IPNet{}
			}
			allocated, err := m.allocator.Allocate(*prefix.Prefix)
			if err != nil {
				m.logger.Debug("Nothing allocated for hinted prefix", zap.Stringer("prefix", prefix))
				continue
			}
			l := record{
				Expire: time.Now().Add(time.Duration(m.LeaseTime)),
				Prefix: allocated,
			}

			addPrefix(iapdResp, l)
			newLeases = append(knownLeases, l)
			m.logger.Debug("allocated prefix", zap.Stringer("prefix", &allocated), zap.Stringer("duid", duidOpt), zap.ByteString("iaid", iapd.IaId[:]))
		}

		if newLeases != nil {
			m.records[duid] = newLeases
		}

		if len(iapdResp.Options.Options) == 0 {
			m.logger.Debug("no valid prefix to return for IAID", zap.ByteString("iaid", iapd.IaId[:]))
			iapdResp.Options.Add(&dhcpv6.OptStatusCode{
				StatusCode: dhcpIana.StatusNoPrefixAvail,
			})
		}

		resp.AddOption(iapdResp)
	}

	return next()
}

// samePrefix returns true if both prefixes are defined and equal
// The empty prefix is equal to nothing, not even itself
func samePrefix(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func addPrefix(resp *dhcpv6.OptIAPD, l record) {
	lifetime := time.Until(l.Expire)

	resp.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: lifetime,
		ValidLifetime:     lifetime,
		Prefix:            dup(&l.Prefix),
	})
}

func dup(src *net.IPNet) (dst *net.IPNet) {
	dst = &net.IPNet{
		IP:   make(net.IP, net.IPv6len),
		Mask: make(net.IPMask, net.IPv6len),
	}
	copy(dst.IP, src.IP)
	copy(dst.Mask, src.Mask)
	return dst
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
