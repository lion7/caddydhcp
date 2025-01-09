// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package nbp

import (
	"encoding/hex"
	"net/url"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// Module implements handling of an NBP (Network Boot Program) using a URL,
// e.g. http://[fe80::abcd:efff:fe12:3456]/my-nbp or tftp://10.0.0.1/my-nbp .
// The NBP information is only added if it is requested by the client.
//
// Note that for DHCPv4, if the URL is prefixed with a "tftp" the URL will
// be split into TFTP server name (option 66) and Bootfile name (option 67),
// so the scheme will be stripped out, and it will be treated as a TFTP URL.
// Anything other than host name and file path will be ignored (no port, no query string, etc).
//
// For DHCPv6 OPT_BOOTFILE_URL (option 59) is used, and the value is passed
// unmodified. If the query string is specified and contains a "param" key,
// its value is also passed as OPT_BOOTFILE_PARAM (option 60), so it will be
// duplicated between option 59 and 60.
type Module struct {
	Urls map[string]string `json:"urls"`

	urls   map[string]*url.URL
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.nbp",
		New: func() caddy.Module { return new(Module) },
	}
}

func (m *Module) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	var urls = make(map[string]*url.URL)
	for k, v := range m.Urls {
		u, err := url.Parse(v)
		if err != nil {
			return err
		}
		urls[k] = u
	}
	m.urls = urls
	return nil
}

func (m *Module) Handle4(req *dhcpv4.DHCPv4, resp *dhcpv4.DHCPv4, next func() error) error {
	if !req.IsOptionRequested(dhcpv4.OptionBootfileName) {
		return next()
	}

	var u *url.URL
	mac := req.ClientHWAddr
	archType := m.extractClientArchType(req.GetOneOption(dhcpv4.OptionClientSystemArchitectureType))
	classId := req.ClassIdentifier()

	// first try to find a URL matching the client MAC
	u = m.urls[mac.String()]

	if u == nil && classId != "" {
		// secondly try to find a URL matching the client class identifier
		u = m.urls[classId]
	}

	if u == nil && archType != nil {
		// lastly try to find a URL matching the client arch type
		key := strconv.Itoa(int(*archType))
		u = m.urls[key]
	}

	if u == nil {
		m.logger.Warn(
			"no boot url found",
			zap.Stringer("mac", mac),
			zap.String("classId", classId),
			zap.Stringer("arch", archType),
		)
		return next()
	}

	m.logger.Info(
		"offering boot url",
		zap.Stringer("mac", mac),
		zap.String("classId", classId),
		zap.Stringer("arch", archType),
		zap.Stringer("url", u),
	)
	switch u.Scheme {
	case "tftp":
		resp.UpdateOption(dhcpv4.OptTFTPServerName(u.Host))
		resp.UpdateOption(dhcpv4.OptBootFileName(u.Path))
	default:
		resp.UpdateOption(dhcpv4.OptBootFileName(u.String()))
	}

	return next()
}

func (m *Module) Handle6(req *dhcpv6.Message, resp dhcpv6.DHCPv6, next func() error) error {
	if !req.IsOptionRequested(dhcpv6.OptionBootfileURL) {
		return next()
	}

	var (
		u             *url.URL
		vendorClass   *dhcpv6.OptVendorClass
		duid, classId string
		archType      *iana.Arch
	)
	{
		opt := req.GetOneOption(dhcpv6.OptionClientID)
		if opt != nil {
			duid = hex.EncodeToString(opt.ToBytes())
		}
	}
	{
		opt := req.GetOneOption(dhcpv6.OptionVendorClass)
		if opt != nil {
			vendorClass = opt.(*dhcpv6.OptVendorClass)
		}
	}
	{
		if vendorClass != nil && len(vendorClass.Data) > 0 {
			classId = string(vendorClass.Data[0])
		}
	}
	{
		opt := req.GetOneOption(dhcpv6.OptionClientArchType)
		if opt != nil {
			archType = m.extractClientArchType(opt.ToBytes())
		}
	}

	if duid != "" {
		// first try to find a URL matching the client ID
		u = m.urls[duid]
	}

	if u == nil && classId != "" {
		// secondly try to find a URL matching the class id
		u = m.urls[classId]
	}

	if u == nil && archType != nil {
		// alternatively try to find a URL matching the client arch type
		key := strconv.Itoa(int(*archType))
		u = m.urls[key]
	}

	if u == nil {
		m.logger.Warn(
			"no boot url found",
			zap.String("duid", duid),
			zap.String("classId", classId),
			zap.Stringer("arch", archType),
		)
		return next()
	}

	m.logger.Info(
		"offering boot url",
		zap.String("duid", duid),
		zap.String("classId", classId),
		zap.Stringer("arch", archType),
		zap.Stringer("url", u),
	)
	if req.IsOptionRequested(dhcpv6.OptionVendorClass) && vendorClass != nil {
		//resp.UpdateOption(vendorClass)
	}
	resp.UpdateOption(dhcpv6.OptBootFileURL(u.String()))
	if req.IsOptionRequested(dhcpv6.OptionBootfileParam) {
		resp.UpdateOption(dhcpv6.OptBootFileParam(u.Query().Get("param")))
	}

	return next()
}

func (m *Module) extractClientArchType(opt []byte) *iana.Arch {
	archTypes := iana.Archs{}
	if err := archTypes.FromBytes(opt); err != nil {
		m.logger.Warn("error parsing client system architecture type", zap.Error(err))
		return nil
	}
	if len(archTypes) > 0 {
		archType := archTypes[0]
		return &archType
	}
	return nil
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
