// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package messagelog

import (
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Prefix string `json:"prefix"`

	logger *zap.Logger
	file   *os.File
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.messagelog",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.file, _ = os.Create(m.Prefix + ".log")
	return nil
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	_, err := fmt.Fprintf(m.file, "Request:\n%s\nResponse:\n%s\n%s\n", req.Summary(), resp.Summary(), strings.Repeat("-", 16))
	if err != nil {
		return err
	}
	return next()
}

func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	_, err := fmt.Fprintf(m.file, "Request:\n%s\nResponse:\n%s\n%s\n", req.Summary(), resp.Summary(), strings.Repeat("-", 16))
	if err != nil {
		return err
	}
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
