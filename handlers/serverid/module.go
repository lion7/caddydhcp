// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package serverid

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

type Module struct {
	Id   string `json:"id,omitempty"`
	Duid string `json:"duid,omitempty"`

	id     net.IP
	duid   dhcpv6.DUID
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.serverid",
		New: func() caddy.Module { return new(Module) },
	}
}

// Provision is run immediately after this handler is being loaded.
func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.Id != "" {
		ip := net.ParseIP(m.Id)
		if ip.To4() == nil {
			return fmt.Errorf("%s is not a valid IPv4 address", m.Id)
		}
		m.id = ip
	}
	if m.Duid != "" {
		split := strings.SplitN(m.Duid, " ", 2)
		if len(split) < 2 {
			return fmt.Errorf("need a DUID type and value")
		}
		duidType := strings.ToLower(split[0])
		if duidType == "" {
			return fmt.Errorf("got empty DUID type")
		}
		duidValue := split[1]
		if duidValue == "" {
			return fmt.Errorf("got empty DUID value")
		}
		switch duidType {
		case "ll", "duid-ll", "duid_ll":
			hwaddr, err := net.ParseMAC(duidValue)
			if err != nil {
				return err
			}
			m.duid = &dhcpv6.DUIDLL{
				// sorry, only ethernet for now
				HWType:        iana.HWTypeEthernet,
				LinkLayerAddr: hwaddr,
			}
		case "llt", "duid-llt", "duid_llt":
			hwaddr, err := net.ParseMAC(duidValue)
			if err != nil {
				return err
			}
			m.duid = &dhcpv6.DUIDLLT{
				// sorry, only ethernet for now
				HWType:        iana.HWTypeEthernet,
				Time:          dhcpv6.GetTime(),
				LinkLayerAddr: hwaddr,
			}
		case "uuid":
			parsedUuid, err := uuid.Parse(duidValue)
			if err != nil {
				return err
			}
			m.duid = &dhcpv6.DUIDUUID{
				UUID: parsedUuid,
			}
		default:
			return fmt.Errorf("opaque DUID type not supported yet")
		}
	}

	return nil
}

// Handle4 handles DHCPv4 packets for this plugin.
func (m *Module) Handle4(_ context.Context, req, resp handlers.DHCPv4, next func() error) error {
	if m.id == nil {
		return next()
	}
	if req.OpCode != dhcpv4.OpcodeBootRequest {
		m.logger.Warn("not a BootRequest, ignoring")
		return next()
	}
	if req.ServerIPAddr != nil &&
		!req.ServerIPAddr.Equal(net.IPv4zero) &&
		!req.ServerIPAddr.Equal(m.id) {
		// This request is not for us, drop it.
		m.logger.Info(fmt.Sprintf("requested server ID does not match this server'm ID. Got %v, want %v", req.ServerIPAddr, m.id))
		return nil
	}
	resp.UpdateOption(dhcpv4.OptServerIdentifier(m.id))
	return next()
}

// Handle6 handles DHCPv6 packets for this plugin.
func (m *Module) Handle6(_ context.Context, req, resp handlers.DHCPv6, next func() error) error {
	if m.duid == nil {
		return next()
	}

	if sid := req.Options.ServerID(); sid != nil {
		// RFC8415 §16.{2,5,7}
		// These message types MUST be discarded if they contain *any* ServerID option
		if req.MessageType == dhcpv6.MessageTypeSolicit ||
			req.MessageType == dhcpv6.MessageTypeConfirm ||
			req.MessageType == dhcpv6.MessageTypeRebind {
			return nil
		}

		// Approximately all others MUST be discarded if the ServerID doesn't match
		if !sid.Equal(m.duid) {
			m.logger.Info(fmt.Sprintf("requested server ID does not match this server'm ID. Got %v, want %v", sid, m.duid))
			return nil
		}
	} else if req.MessageType == dhcpv6.MessageTypeRequest ||
		req.MessageType == dhcpv6.MessageTypeRenew ||
		req.MessageType == dhcpv6.MessageTypeDecline ||
		req.MessageType == dhcpv6.MessageTypeRelease {
		// RFC8415 §16.{6,8,10,11}
		// These message types MUST be discarded if they *don't* contain a ServerID option
		return nil
	}
	dhcpv6.WithServerID(m.duid)(resp)
	return next()
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
