// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package example

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// Module is an example that inspects a packet and prints it out with a configurable prefix.
// The code is commented in a way that should walk you through the implementation of your own handler.
// Feedback is welcome!
type Module struct {
	// You can add fields here that are necessary to configure this handler.
	// In this example, a single field 'prefix' is available.
	Prefix string `json:"prefix,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
// Note that the ID should start with 'dhcp.handlers.'. The last part is this handlers name.
// It must be unique to other registered handlers, or the operation will fail.
// In other words, don't declare handlers with colliding names.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.example",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
// You can use this to perform some additional "setup" steps, e.g. retrieving a logger from the caddy.Context.
// Provisioning should be fast (imperceptible running time).
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

// Handle4 behaves like Handle6, but for DHCPv4 packets.
func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	m.logger.Info(fmt.Sprintf("%s: received DHCPv4 packet", m.Prefix), zap.String("summary", req.Summary()))
	return next()
}

// Handle6 handles DHCPv6 packets for the example plugin.
// The input arguments are the request packet that the server received from a client,
// and the response packet that has been computed so far.
// The next function will never be nil, but may be a no-op handler if this is the last handler in the chain.
// Handlers which act as middleware should call the next function to propagate the request down the chain properly.
// Handlers which act as responders (content origins) need not invoke the next function,
// since the last handler in the chain should be the first to write the response.
func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	m.logger.Info(fmt.Sprintf("%s: received DHCPv6 packet", m.Prefix), zap.String("summary", req.Summary()))
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
