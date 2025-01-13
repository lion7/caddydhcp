// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package staticroute

import (
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Routes []string `json:"routes,omitempty"`

	routes dhcpv4.Routes
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.staticroute",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	var routes dhcpv4.Routes
	for _, arg := range m.Routes {
		fields := strings.Split(arg, ",")
		if len(fields) != 2 {
			return fmt.Errorf("expected a destination/gateway pair, got: " + arg)
		}

		_, dest, err := net.ParseCIDR(fields[0])
		if err != nil {
			return fmt.Errorf("expected a destination subnet, got: " + fields[0])
		}

		router := net.ParseIP(fields[1])
		if router == nil {
			return fmt.Errorf("expected a gateway address, got: " + fields[1])
		}

		route := &dhcpv4.Route{
			Dest:   dest,
			Router: router,
		}
		routes = append(routes, route)
		m.logger.Info("adding static route", zap.Stringer("route", route))
	}
	m.logger.Info(fmt.Sprintf("loaded %d static routes.", len(routes)))
	m.routes = routes
	return nil
}

// Handle4 handles DHCPv4 packets for this plugin.
func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if req.IsOptionRequested(dhcpv4.OptionDomainNameServer) {
		resp.UpdateOption(dhcpv4.OptClasslessStaticRoute(m.routes...))
	}
	return next()
}

// Handle6 handles DHCPv6 packets for this plugin.
func (m *Module) Handle6(_, _ handlers.DHCPv6, next func() error) error {
	// staticroute does not apply to DHCPv6, so just continue the chain
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
