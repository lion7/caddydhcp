// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package autoconfigure

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// Module implements RFC2563:
//  1. If the client has been allocated an IP address, do nothing
//  2. If the client has not been allocated an IP address
//     (YourIPAddr=0.0.0.0), then:
//     2a. If the client has requested the "Module" option,
//     then add the defined value to the response
//     2b. Otherwise, terminate processing and send no reply
//
// This module should be used at the end of the chain,
// after any IP address allocation has taken place.
//
// The optional argument is the string "DoNotAutoConfigure" or
// "Module" (or "0" or "1" respectively).  The default
// is DoNotAutoConfigure.
type Module struct {
	AutoConfigure bool `json:"autoconfigure"`

	autoConfigure dhcpv4.AutoConfiguration
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.autoconfigure",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if m.AutoConfigure {
		m.autoConfigure = dhcpv4.AutoConfigure
	} else {
		m.autoConfigure = dhcpv4.DoNotAutoConfigure
	}
	return nil
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if resp.MessageType() != dhcpv4.MessageTypeOffer || !resp.YourIPAddr.IsUnspecified() {
		return next()
	}

	ac, ok := req.AutoConfigure()
	if ok {
		resp.UpdateOption(dhcpv4.OptAutoConfigure(m.autoConfigure))
		m.logger.Debug(
			"responded with autoconfigure",
			zap.String("mac", req.ClientHWAddr.String()),
			zap.String("autoconfigure", ac.String()),
		)
		return next()
	}

	m.logger.Debug(
		"client does not support autoconfigure",
		zap.String("mac", req.ClientHWAddr.String()),
	)
	// RFC2563 2.3: if no address is chosen for the host [...]
	// If the DHCPDISCOVER does not contain the Auto-Configure option,
	// it is not answered.
	return nil
}

func (m *Module) Handle6(_, _ handlers.DHCPv6, next func() error) error {
	// autoconfigure does not apply to DHCPv6, so just continue the chain
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
