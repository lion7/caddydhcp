package handlers

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// A Handler that responds to an DHCPv4 or DHCPv6 request.
// The next handler will never be nil, but may be a no-op handler.
// Handlers which act as middleware should call the next handler's Handle6
// method so as to propagate the request down the chain properly.
// Handlers which act as responders (content origins) need not invoke the next handler,
// since the last handler in the chain should be the first to write the response.
//
// If any handler encounters an error, it should be returned for proper
// handling. Return values should be propagated down the middleware chain
// by returning it unchanged. Returned errors should not be re-wrapped
// if they are already HandlerError values.
type Handler interface {
	Handle4(req, resp *dhcpv4.DHCPv4, next func() error) error
	Handle6(req *dhcpv6.Message, resp dhcpv6.DHCPv6, next func() error) error
}

// A HandlerModule is a Handler that also implements
// the caddy.Module and caddy.Provisioner interfaces.
type HandlerModule interface {
	caddy.Module
	caddy.Provisioner
	Handler
}
