// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package rangeplugin

import (
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/lion7/caddydhcp/handlers/allocators"
	"github.com/lion7/caddydhcp/handlers/allocators/bitmap"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.range",
		New: func() caddy.Module { return new(Module) },
	}
}

type Module struct {
	Filename  string         `json:"filename"`
	StartIP   string         `json:"startIP"`
	EndIP     string         `json:"endIP"`
	LeaseTime caddy.Duration `json:"leaseTime,omitempty"`

	logger    *zap.Logger
	allocator allocators.Allocator
	leaseDb   *sql.DB
	recLock   *sync.RWMutex
	records4  map[string]record
	records6  map[string]record
}

// record holds an IP lease record
type record struct {
	IP       net.IP
	expires  int
	hostname string
}

func (m *Module) Provision(ctx caddy.Context) error {
	var err error
	m.logger = ctx.Logger()
	m.recLock = &sync.RWMutex{}
	ipRangeStart := net.ParseIP(m.StartIP)
	if ipRangeStart.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %v", m.StartIP)
	}
	ipRangeEnd := net.ParseIP(m.EndIP)
	if ipRangeEnd.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %v", m.EndIP)
	}
	if binary.BigEndian.Uint32(ipRangeStart.To4()) >= binary.BigEndian.Uint32(ipRangeEnd.To4()) {
		return fmt.Errorf("start of IP range has to be lower than the end of an IP range")
	}

	m.allocator, err = bitmap.NewIPv4Allocator(ipRangeStart, ipRangeEnd)
	if err != nil {
		return fmt.Errorf("could not create an allocator: %w", err)
	}
	m.leaseDb, err = loadDB(m.Filename)
	if err != nil {
		return fmt.Errorf("failed to load lease database %s: %w", m.Filename, err)
	}
	m.recLock.Lock()
	defer m.recLock.Unlock()
	m.records4, err = loadRecords4(m.leaseDb)
	if err != nil {
		return fmt.Errorf("failed to load DHCPv4 records: %w", err)
	}
	for _, v := range m.records4 {
		ipNet, err := m.allocator.Allocate(net.IPNet{IP: v.IP})
		if err != nil {
			return fmt.Errorf("failed to re-allocate leased ip %v: %v", v.IP.String(), err)
		}
		if ipNet.IP.String() != v.IP.String() {
			return fmt.Errorf("allocator did not re-allocate requested leased ip %v: %v", v.IP.String(), ipNet.String())
		}
	}
	return nil
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	m.logger.Debug("looking up an IP address for MAC", zap.Stringer("mac", req.ClientHWAddr))
	ip, err := m.lookup4(req.ClientHWAddr, req.HostName())
	if err != nil {
		m.logger.Warn("MAC address is unknown", zap.Stringer("mac", req.ClientHWAddr))
		return next()
	}

	resp.YourIPAddr = ip
	m.logger.Info("found IP address for MAC", zap.Stringer("mac", req.ClientHWAddr), zap.Stringer("ip", ip))
	return next()
}

func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	if req.Options.OneIANA() == nil {
		m.logger.Debug("no address requested")
		return next()
	}

	duidOpt := req.Options.ClientID()
	duid := hex.EncodeToString(duidOpt.ToBytes())

	m.logger.Info("looking up an IP address for DUID", zap.String("duid", duid))
	ip, err := m.lookup6(duid)
	if err != nil {
		m.logger.Warn("DUID is unknown", zap.String("duid", duid))
		return next()
	}

	resp.AddOption(&dhcpv6.OptIANA{
		IaId: req.Options.OneIANA().IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          ip,
				PreferredLifetime: 3600 * time.Second,
				ValidLifetime:     3600 * time.Second,
			},
		}},
	})
	m.logger.Info("found IP address for DUID", zap.String("duid", duid), zap.Stringer("ip", ip))
	return next()
}

func (m *Module) lookup4(addr net.HardwareAddr, hostname string) (net.IP, error) {
	m.recLock.RLock()
	defer m.recLock.RUnlock()
	rec, ok := m.records4[addr.String()]
	if !ok {
		// Allocating new address since there isn't one allocated
		m.logger.Info("leasing new IPv4 address", zap.Stringer("mac", addr))
		ip, err := m.allocator.Allocate(net.IPNet{})
		if err != nil {
			return nil, fmt.Errorf("could not allocate IP for MAC %s: %v", addr.String(), err)
		}
		newRec := record{
			IP:       ip.IP.To4(),
			expires:  int(time.Now().Add(time.Duration(m.LeaseTime)).Unix()),
			hostname: hostname,
		}
		err = saveIPAddress(m.leaseDb, addr, newRec)
		if err != nil {
			return nil, fmt.Errorf("SaveIPAddress for MAC %s failed: %v", addr.String(), err)
		}
		m.records4[addr.String()] = newRec
		rec = newRec
	} else {
		// Ensure we extend the existing lease at least past when the one we're giving expires
		expiry := time.Unix(int64(rec.expires), 0)
		if expiry.Before(time.Now().Add(time.Duration(m.LeaseTime))) {
			rec.expires = int(time.Now().Add(time.Duration(m.LeaseTime)).Round(time.Second).Unix())
			rec.hostname = hostname
			err := saveIPAddress(m.leaseDb, addr, rec)
			if err != nil {
				return nil, fmt.Errorf("could not persist lease for MAC %s: %v", addr.String(), err)
			}
		}
	}
	return rec.IP, nil
}

func (m *Module) lookup6(encodedDuid string) (net.IP, error) {
	m.recLock.RLock()
	defer m.recLock.RUnlock()
	rec, _ := m.records6[encodedDuid]
	return rec.IP, nil
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
