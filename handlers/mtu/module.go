// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package mtu

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Mtu int `json:"mtu"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.mtu",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if req.IsOptionRequested(dhcpv4.OptionInterfaceMTU) {
		resp.UpdateOption(dhcpv4.Option{Code: dhcpv4.OptionInterfaceMTU, Value: dhcpv4.Uint16(m.Mtu)})
	}
	return next()
}

func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	// DHCPv6 does not have MTU-related options, so just continue the chain
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
