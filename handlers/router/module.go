// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package router

import (
	"context"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Routers []string `json:"routers"`

	routers []net.IP
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.router",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	var routers []net.IP
	for _, r := range m.Routers {
		router := net.ParseIP(r)
		if router.To4() == nil {
			return fmt.Errorf("expected an router IP address, got: %s", router)
		}
		routers = append(routers, router)
	}
	m.routers = routers
	return nil
}

func (m *Module) Handle4(_ context.Context, _, resp handlers.DHCPv4, next func() error) error {
	resp.UpdateOption(dhcpv4.OptRouter(m.routers...))
	return next()
}

func (m *Module) Handle6(_ context.Context, _, _ handlers.DHCPv6, next func() error) error {
	// router does not apply to DHCPv6, so just continue the chain
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
