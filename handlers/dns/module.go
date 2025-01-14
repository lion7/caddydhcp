// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package dns

import (
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Servers []string `json:"servers,omitempty"`

	servers4 []net.IP
	servers6 []net.IP
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.dns",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	var servers4, servers6 []net.IP
	for _, server := range m.Servers {
		ip := net.ParseIP(server)
		isIPv6 := ip.To4() == nil
		if isIPv6 {
			servers6 = append(servers6, ip)
		} else {
			servers4 = append(servers4, ip)
		}
	}
	m.servers4 = servers4
	m.servers6 = servers6
	return nil
}

// Handle4 handles DHCPv4 packets for this plugin.
func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if req.IsOptionRequested(dhcpv4.OptionDomainNameServer) {
		resp.UpdateOption(dhcpv4.OptDNS(m.servers4...))
	}
	return next()
}

// Handle6 handles DHCPv6 packets for this plugin.
func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	if req.IsOptionRequested(dhcpv6.OptionDNSRecursiveNameServer) {
		resp.UpdateOption(dhcpv6.OptDNS(m.servers6...))
	}
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
