// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package ipv6only

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// Module implements RFC8925: if the client has requested the
// IPv6-Only Preferred option, then add the option response and then
// terminate processing immediately.
//
// This module should be invoked *before* any IP address
// allocation has been done, so that the YourIPAddr is 0.0.0.0
// and no pool addresses are consumed for compatible clients.
//
// The optional argument is the V6ONLY_WAIT configuration variable,
// described in RFC8925 section 3.2.
type Module struct {
	Wait caddy.Duration `json:"wait,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.ipv6only",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if req.IsOptionRequested(dhcpv4.OptionIPv6OnlyPreferred) {
		resp.UpdateOption(dhcpv4.OptIPv6OnlyPreferred(time.Duration(m.Wait)))
	}
	return next()
}

func (m *Module) Handle6(_, _ handlers.DHCPv6, next func() error) error {
	// ipv6-only does not apply to DHCPv6, so just continue the chain
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
