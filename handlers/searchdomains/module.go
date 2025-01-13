// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package searchdomains

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// Module adds default DNS search domains.
type Module struct {
	Domains []string `json:"domains,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.searchdomains",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

// Handle4 handles DHCPv4 packets for this plugin.
func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if req.IsOptionRequested(dhcpv4.OptionDNSDomainSearchList) {
		resp.UpdateOption(dhcpv4.OptDomainSearch(&rfc1035label.Labels{Labels: copySlice(m.Domains)}))
	}
	return next()
}

// Handle6 handles DHCPv6 packets for this plugin.
func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	if req.IsOptionRequested(dhcpv6.OptionDomainSearchList) {
		resp.UpdateOption(dhcpv6.OptDomainSearchList(&rfc1035label.Labels{Labels: copySlice(m.Domains)}))
	}
	return next()
}

// copySlice creates a new copy of a string slice in memory.
// This helps to ensure that downstream plugins can't corrupt
// this plugin's configuration
func copySlice(original []string) []string {
	copied := make([]string, len(original))
	copy(copied, original)
	return copied
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
