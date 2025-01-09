// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package sleep

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// Module introduces a delay in the DHCP response.
type Module struct {
	Duration caddy.Duration `json:"duration"`
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.sleep",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

func (m *Module) Handle4(_ *dhcpv4.DHCPv4, _ *dhcpv4.DHCPv4, next func() error) error {
	delay := time.Duration(m.Duration)
	m.logger.Info("introducing delay in response", zap.Duration("delay", delay))
	time.Sleep(delay)
	return next()
}

func (m *Module) Handle6(_ *dhcpv6.Message, _ dhcpv6.DHCPv6, next func() error) error {
	delay := time.Duration(m.Duration)
	m.logger.Info("introducing delay in response", zap.Duration("delay", delay))
	time.Sleep(delay)
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
