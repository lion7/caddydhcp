// Copyright 2018-present the CoreDHCP Authors. All rights reserved
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package file

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/lion7/caddydhcp/handlers"
	"go.uber.org/zap"
)

// CaddyModule returns the Caddy module information.
func (Module) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp.handlers.file",
		New: func() caddy.Module { return new(Module) },
	}
}

// Module enables static mapping of MAC <--> IP addresses.
// The mapping is stored in a text file, where each mapping is described by one line containing
// two fields separated by spaces: MAC address, and IP address. For example:
//
//	$ cat file_leases.txt
//	00:11:22:33:44:55 10.0.0.1
//	01:23:45:67:89:ab 10.0.10.10
//	02:34:56:78:9a:bc 2001:db8::1
//	03:45:67:89:ab:cd 2001:db8:3333:4444:5555:6666:7777:8888
//
// If the file path is not absolute, it is relative to the cwd where caddydhcp is run.
//
// Optionally, when the 'autoRefresh' argument is true, the plugin will try to refresh
// the lease mapping during runtime whenever the lease file is updated.
type Module struct {
	Filename    string `json:"filename"`
	AutoRefresh bool   `json:"autoRefresh"`

	logger   *zap.Logger
	recLock  *sync.RWMutex
	records4 map[string]net.IP
	records6 map[string]net.IP
}

func (m *Module) Provision(ctx caddy.Context) error {
	ctx.Slogger()
	m.logger = ctx.Logger()
	m.recLock = &sync.RWMutex{}
	// when auto refresh is enabled, watch the lease file for
	// changes and reload the lease mapping on any event
	if m.AutoRefresh {
		return m.watchRecords()
	} else {
		return m.loadRecords()
	}
}

func (m *Module) Handle4(req, resp handlers.DHCPv4, next func() error) error {

	m.logger.Debug("looking up an IP address for MAC", zap.String("mac", req.ClientHWAddr.String()))
	ip, ok := m.lookup4(req.ClientHWAddr)
	if !ok {
		m.logger.Warn("MAC address is unknown", zap.String("mac", req.ClientHWAddr.String()))
		return next()
	}

	resp.YourIPAddr = ip
	m.logger.Info("found IP address for MAC", zap.String("mac", req.ClientHWAddr.String()), zap.String("ip", ip.String()))
	return next()
}

func (m *Module) Handle6(req, resp handlers.DHCPv6, next func() error) error {
	if req.Options.OneIANA() == nil {
		m.logger.Debug("no address requested")
		return next()
	}

	duidOpt := req.GetOneOption(dhcpv6.OptionClientID).(dhcpv6.DUID)
	duid := hex.EncodeToString(duidOpt.ToBytes())

	m.logger.Info("looking up an IP address for DUID", zap.String("duid", duid))
	ip, ok := m.lookup6(duid)
	if !ok {
		m.logger.Warn("DUID is unknown", zap.String("duid", duid))
		return next()
	}

	resp.AddOption(&dhcpv6.OptIANA{
		IaId: req.Options.OneIANA().IaId,
		Options: dhcpv6.IdentityOptions{Options: []dhcpv6.Option{
			&dhcpv6.OptIAAddress{
				IPv6Addr:          ip,
				PreferredLifetime: 3600 * time.Second,
				ValidLifetime:     3600 * time.Second,
			},
		}},
	})
	m.logger.Info("found IP address for DUID", zap.String("duid", duid), zap.String("ip", ip.String()))
	return next()
}

func (m *Module) lookup4(addr net.HardwareAddr) (net.IP, bool) {
	m.recLock.RLock()
	defer m.recLock.RUnlock()
	ip, ok := m.records4[addr.String()]
	return ip, ok
}

func (m *Module) lookup6(encodedDuid string) (net.IP, bool) {
	m.recLock.RLock()
	defer m.recLock.RUnlock()
	ip, ok := m.records6[encodedDuid]
	return ip, ok
}

// loadRecords loads the records map with records stored in the specified file.
// The records have to be one per line, a mac address and an IP address.
func (m *Module) loadRecords() error {
	m.logger.Debug("reading leases", zap.String("filename", m.Filename))
	data, err := os.ReadFile(m.Filename)
	if err != nil {
		return err
	}
	records4 := make(map[string]net.IP)
	records6 := make(map[string]net.IP)
	for _, lineBytes := range bytes.Split(data, []byte{'\n'}) {
		line := string(lineBytes)
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) != 2 {
			return fmt.Errorf("malformed line, want 2 fields, got %d: %s", len(tokens), line)
		}
		id := tokens[0]
		ip := net.ParseIP(tokens[1])
		if ip.To4() != nil {
			records4[id] = ip
		}
		if ip.To16() != nil {
			records6[id] = ip
		}
	}
	m.logger.Info(fmt.Sprintf("loaded %d DHCPv4 leases and %d DHCPv6 leases", len(records4), len(records6)), zap.String("filename", m.Filename))

	m.recLock.RLock()
	defer m.recLock.RUnlock()
	m.records4 = records4
	m.records6 = records6
	return nil
}

func (m *Module) watchRecords() error {
	// initially load the records
	err := m.loadRecords()
	if err != nil {
		return err
	}

	// creates a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	// have file watcher watch over lease file
	if err = watcher.Add(m.Filename); err != nil {
		return fmt.Errorf("failed to watch %s: %w", m.Filename, err)
	}

	// very simple watcher on the lease file to trigger a refresh on any event
	// on the file
	go func() {
		for event := range watcher.Events {
			if event.Op&fsnotify.Write == fsnotify.Write {
				m.logger.Info("file changed", zap.String("filename", m.Filename))
				if err := m.loadRecords(); err != nil {
					m.logger.Error("failed to refresh records", zap.Error(err))
				}
			}
		}
	}()
	return nil
}

// Interfaces guards
var (
	_ handlers.HandlerModule = (*Module)(nil)
)
