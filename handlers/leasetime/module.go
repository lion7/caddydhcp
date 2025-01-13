// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package leasetime

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Time caddy.Duration `json:"time"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.leasetime",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if req.OpCode != dhcpv4.OpcodeBootRequest && req.IsOptionRequested(dhcpv4.OptionIPAddressLeaseTime) {
		resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Duration(m.Time)))
	}
	return next()
}

func (m *Module) Handle6(_, _ handlers.DHCPv6, next func() error) error {
	// lease time does not apply to DHCPv6, so just continue the chain
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
