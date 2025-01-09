// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package netmask

import (
	"encoding/binary"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
	"net"
)

type Module struct {
	Netmask string `json:"netmask"`

	netmask net.IPMask
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.netmask",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	ip := net.ParseIP(m.Netmask)
	if ip.IsUnspecified() {
		return fmt.Errorf("netmask is not valid, got: %s", m.Netmask)
	}
	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("expected an netmask address, got: %s", m.Netmask)
	}
	netmask := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3])
	if !checkValidNetmask(netmask) {
		return fmt.Errorf("netmask is not valid, got: %s", m.Netmask)
	}
	m.netmask = netmask
	return nil
}

func (m *Module) Handle4(_ *dhcpv4.DHCPv4, resp *dhcpv4.DHCPv4, next func() error) error {
	resp.UpdateOption(dhcpv4.OptSubnetMask(m.netmask))
	return next()
}

func (m *Module) Handle6(_ *dhcpv6.Message, _ dhcpv6.DHCPv6, next func() error) error {
	// netmask does not apply to DHCPv6, so just continue the chain
	return next()
}

func checkValidNetmask(netmask net.IPMask) bool {
	netmaskInt := binary.BigEndian.Uint32(netmask)
	x := ^netmaskInt
	y := x + 1
	return (y & x) == 0
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
