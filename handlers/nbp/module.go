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

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {
	if !req.IsOptionRequested(dhcpv4.OptionBootfileName) {
		return next()
	}

	mac := req.ClientHWAddr
	archTypes := req.ClientArch()
	classId := req.ClassIdentifier()

	u := m.findUrl(mac.String(), []string{classId}, archTypes)
	if u == nil {
		m.logger.Warn(
			"no boot url found",
			zap.Stringer("mac", mac),
			zap.String("classId", classId),
			zap.Stringers("archTypes", archTypes),
		)
		return next()
	}

	m.logger.Info(
		"offering boot url",
		zap.Stringer("mac", mac),
		zap.String("classId", classId),
		zap.Stringers("archTypes", archTypes),
		zap.Stringer("url", u),
	)
	switch u.Scheme {
	case "tftp":
		resp.UpdateOption(dhcpv4.OptTFTPServerName(u.Host))
		resp.UpdateOption(dhcpv4.OptBootFileName(u.Path))
	default:
		resp.UpdateOption(dhcpv4.OptBootFileName(u.String()))
	}

	if req.IsOptionRequested(dhcpv4.OptionClassIdentifier) {
		resp.UpdateOption(dhcpv4.OptClassIdentifier(classId))
	}

	return next()
}

func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	if !req.IsOptionRequested(dhcpv6.OptionBootfileURL) {
		return next()
	}

	clientId := req.Options.ClientID()
	encodedClientId := hex.EncodeToString(clientId.ToBytes())
	classIds := mapToClassIds(req.Options.VendorClasses())
	archTypes := req.Options.ArchTypes()

	u := m.findUrl(encodedClientId, classIds, archTypes)
	if u == nil {
		m.logger.Warn(
			"no boot url found",
			zap.Stringer("clientId", clientId),
			zap.Strings("classIds", classIds),
			zap.Stringer("archTypes", archTypes),
		)
		return next()
	}

	m.logger.Info(
		"offering boot url",
		zap.Stringer("clientId", clientId),
		zap.Strings("classIds", classIds),
		zap.Stringer("archTypes", archTypes),
		zap.Stringer("url", u),
	)
	resp.UpdateOption(dhcpv6.OptBootFileURL(u.String()))
	if req.IsOptionRequested(dhcpv6.OptionBootfileParam) {
		resp.UpdateOption(dhcpv6.OptBootFileParam(u.Query().Get("param")))
	}

	if req.IsOptionRequested(dhcpv6.OptionVendorClass) && req.Options.VendorClasses() != nil {
		for _, class := range req.Options.VendorClasses() {
			resp.UpdateOption(class)
		}
	}

	return next()
}

func (m *Module) findUrl(clientId string, classIds []string, archTypes iana.Archs) *url.URL {
	if clientId != "" {
		// first try to find a URL matching the client ID
		u := m.urls[clientId]
		if u != nil {
			return u
		}
	}

	if classIds != nil {
		// secondly try to find a URL matching one of the class id's
		for _, classId := range classIds {
			u := m.urls[classId]
			if u != nil {
				return u
			}
		}
	}

	if archTypes != nil {
		// alternatively try to find a URL matching one of the client arch types
		for _, archType := range archTypes {
			key := strconv.Itoa(int(archType))
			u := m.urls[key]
			if u != nil {
				return u
			}
		}
	}

	return nil
}

func mapToClassIds(vendorClasses []*dhcpv6.OptVendorClass) []string {
	if vendorClasses == nil {
		return nil
	}
	var classIds []string
	for _, vendorClass := range vendorClasses {
		for _, data := range vendorClass.Data {
			classIds = append(classIds, string(data))
		}
	}
	return classIds
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
