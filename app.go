package caddydhcp

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/lion7/caddydhcp/handlers"
	"github.com/lion7/caddydhcp/handlers/autoconfigure"
	"github.com/lion7/caddydhcp/handlers/dns"
	"github.com/lion7/caddydhcp/handlers/example"
	"github.com/lion7/caddydhcp/handlers/file"
	"github.com/lion7/caddydhcp/handlers/ipv6only"
	"github.com/lion7/caddydhcp/handlers/leasetime"
	"github.com/lion7/caddydhcp/handlers/mtu"
	"github.com/lion7/caddydhcp/handlers/nbp"
	"github.com/lion7/caddydhcp/handlers/netmask"
	"github.com/lion7/caddydhcp/handlers/router"
	"github.com/lion7/caddydhcp/handlers/serverid"
	"github.com/lion7/caddydhcp/handlers/sleep"
)

func init() {
	// register this app module
	caddy.RegisterModule(App{})

	// register handler modules
	caddy.RegisterModule(autoconfigure.Module{})
	caddy.RegisterModule(dns.Module{})
	caddy.RegisterModule(example.Module{})
	caddy.RegisterModule(file.Module{})
	caddy.RegisterModule(ipv6only.Module{})
	caddy.RegisterModule(leasetime.Module{})
	caddy.RegisterModule(mtu.Module{})
	caddy.RegisterModule(nbp.Module{})
	caddy.RegisterModule(netmask.Module{})
	caddy.RegisterModule(router.Module{})
	caddy.RegisterModule(serverid.Module{})
	caddy.RegisterModule(sleep.Module{})
}

type App struct {
	Servers map[string]*Server `json:"servers,omitempty"`

	servers  []*dhcpServer
	ctx      caddy.Context
	errGroup *errgroup.Group
}

type Server struct {
	// Network interfaces to which to bind listeners.
	// By default, all interfaces are bound.
	Interfaces []string `json:"interfaces,omitempty"`

	// Socket addresses to which to bind listeners.
	// Accepts network addresses that may include ports.
	// Listener addresses must be unique; they cannot be repeated across all defined servers.
	// The default addresses are `0.0.0.0:69` and `[::]:547`.
	Addresses []string `json:"addresses,omitempty"`

	// Enables access logging.
	Logs bool `json:"logs,omitempty"`

	// The list of handlers for this server. They are chained
	// together in a middleware fashion: requests flow from the first handler to the last
	// (top of the list to the bottom), with the possibility that any handler could stop
	// the chain and/or return an error. Responses flow back through the chain (bottom of
	// the list to the top) as they are written out to the client.
	//
	// Not all handlers call the next handler in the chain.
	// The documentation for a module should state whether it invokes
	// the next handler, but sometimes it is common sense.
	//
	// Some handlers manipulate the response. Remember that requests flow down the list, and
	// responses flow up the list.
	HandlersRaw []json.RawMessage `json:"handle,omitempty" caddy:"namespace=dhcp.handlers inline_key=handler"`
}

type dhcpServer struct {
	name       string
	interfaces []string
	addresses  []*net.UDPAddr
	handler    handlers.Handler
	logger     *zap.Logger
	accessLog  *zap.Logger

	servers4 []*server4.Server
	servers6 []*server6.Server
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp",
		New: func() caddy.Module { return new(App) },
	}
}

func (app *App) Provision(ctx caddy.Context) error {
	app.ctx = ctx
	for name, srv := range app.Servers {
		interfaces := srv.Interfaces
		if len(interfaces) == 0 {
			interfaces = []string{""}
		}

		addresses, err := parseAddresses(srv.Addresses)
		if err != nil {
			return err
		} else if len(addresses) == 0 {
			addresses = append(addresses, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort})
			addresses = append(addresses, &net.UDPAddr{IP: net.IPv6unspecified, Port: dhcpv6.DefaultServerPort})
		}

		handler, err := compileHandlerChain(ctx, srv)
		if err != nil {
			return err
		}

		logger := ctx.Logger().Named(name)
		s := &dhcpServer{
			name:       name,
			interfaces: interfaces,
			addresses:  addresses,
			handler:    handler,
			logger:     logger,
			accessLog:  logger.Named("access"),
		}

		app.servers = append(app.servers, s)
	}
	return nil
}

// Start starts the app.
func (app *App) Start() error {
	app.errGroup = &errgroup.Group{}
	for _, s := range app.servers {
		for _, iface := range s.interfaces {
			for _, addr := range s.addresses {
				isIPv6 := addr.IP.To4() == nil
				if isIPv6 {
					server, err := server6.NewServer(
						iface,
						addr,
						s.handle6,
						server6.WithLogger(server6.ShortSummaryLogger{Printfer: s}),
					)
					if err != nil {
						return fmt.Errorf("failed to listen on %s: %v", addr, err)
					}
					app.errGroup.Go(func() error {
						return server.Serve()
					})
					s.servers6 = append(s.servers6, server)
				} else {
					server, err := server4.NewServer(
						iface,
						addr,
						s.handle4,
						server4.WithLogger(server4.ShortSummaryLogger{Printfer: s}),
					)
					if err != nil {
						return fmt.Errorf("failed to listen on %s: %v", addr, err)
					}
					app.errGroup.Go(func() error {
						return server.Serve()
					})
					s.servers4 = append(s.servers4, server)
				}
			}
		}

		s.logger.Info(
			"server running",
			zap.String("name", s.name),
			zap.Strings("interfaces", s.interfaces),
			zap.Stringers("addresses", s.addresses),
		)
	}
	return nil
}

// Stop stops the app.
func (app *App) Stop() error {
	for _, s := range app.servers {
		for _, server := range s.servers4 {
			if err := server.Close(); err != nil {
				return err
			}
		}
		for _, server := range s.servers6 {
			if err := server.Close(); err != nil {
				return err
			}
		}
		s.logger.Info(
			"server stopped",
			zap.String("name", s.name),
			zap.Strings("interfaces", s.interfaces),
			zap.Stringers("addresses", s.addresses),
		)
	}
	return app.errGroup.Wait()
}

func (s *dhcpServer) handle4(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	var (
		req, resp *dhcpv4.DHCPv4
		err       error
		n         int
	)

	if s.accessLog != nil {
		var remoteIP net.IP
		var remotePort int
		if udpAddr, ok := peer.(*net.UDPAddr); ok {
			remoteIP = udpAddr.IP
			remotePort = udpAddr.Port
		}
		start := time.Now()
		defer func() {
			end := time.Now()
			d := end.Sub(start)
			s.accessLog.Info(
				"handled request",
				zap.String("remote_ip", remoteIP.String()),
				zap.Int("remote_port", remotePort),
				zap.String("message_type", m.MessageType().String()),
				zap.Int("bytes_written", n),
				zap.String("duration", d.String()),
			)
		}()
	}

	req = m
	s.logger.Debug("received message", zap.String("message", req.Summary()))

	resp, err = dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		s.Printf("handle4: failed to build reply: %v", err)
		return
	}
	switch mt := req.MessageType(); mt {
	case dhcpv4.MessageTypeDiscover:
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	case dhcpv4.MessageTypeRequest:
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	default:
		s.Printf("handle4: unhandled message type: %v", mt)
		return
	}

	err = s.handler.Handle4(req, resp, func() error { return nil })
	if err != nil {
		s.logger.Error("handler chain failed", zap.Error(err))
		return
	}

	if resp != nil {
		n, err = conn.WriteTo(resp.ToBytes(), peer)
		if err != nil {
			s.logger.Error(err.Error())
		}
		s.logger.Debug("send message", zap.String("message", resp.Summary()))
	}
}

func (s *dhcpServer) Printf(format string, v ...interface{}) {
	s.logger.Debug(fmt.Sprintf(format, v...))
}

func (s *dhcpServer) handle6(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
	var (
		req  *dhcpv6.Message
		resp dhcpv6.DHCPv6
		err  error
		n    int
	)

	if s.accessLog != nil {
		var remoteIP net.IP
		var remotePort int
		if udpAddr, ok := peer.(*net.UDPAddr); ok {
			remoteIP = udpAddr.IP
			remotePort = udpAddr.Port
		}
		start := time.Now()
		defer func() {
			end := time.Now()
			d := end.Sub(start)
			s.accessLog.Info(
				"handled request",
				zap.String("remote_ip", remoteIP.String()),
				zap.Int("remote_port", remotePort),
				zap.String("message_type", m.Type().String()),
				zap.Int("bytes_written", n),
				zap.String("duration", d.String()),
			)
		}()
	}

	req, err = m.GetInnerMessage()
	if err != nil {
		s.logger.Error("cannot get inner message", zap.Error(err))
		return
	}
	s.logger.Debug("received message", zap.String("message", req.Summary()))

	switch req.Type() {
	case dhcpv6.MessageTypeSolicit:
		if req.GetOneOption(dhcpv6.OptionRapidCommit) != nil {
			resp, err = dhcpv6.NewReplyFromMessage(req)
		} else {
			resp, err = dhcpv6.NewAdvertiseFromSolicit(req)
		}
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRenew,
		dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeInformationRequest:
		resp, err = dhcpv6.NewReplyFromMessage(req)
	default:
		err = fmt.Errorf("message type %d not supported", req.Type())
	}
	if err != nil {
		s.logger.Error("NewReplyFromDHCPv6Message failed", zap.Error(err))
		return
	}

	err = s.handler.Handle6(req, resp, func() error { return nil })
	if err != nil {
		s.logger.Error("handler chain failed", zap.Error(err))
		return
	}

	// if the request was relayed, re-encapsulate the response
	if m.IsRelay() {
		if rmsg, ok := resp.(*dhcpv6.Message); !ok {
			s.logger.Error("response is a relayed message, not re-encapsulating")
		} else {
			tmp, err := dhcpv6.NewRelayReplFromRelayForw(m.(*dhcpv6.RelayMessage), rmsg)
			if err != nil {
				s.logger.Error("cannot create relay-repl from relay-forw", zap.Error(err))
				return
			}
			resp = tmp
		}
	}

	if resp != nil {
		n, err = conn.WriteTo(resp.ToBytes(), peer)
		if err != nil {
			s.logger.Error(err.Error())
		}
		if rmsg, err := resp.GetInnerMessage(); err != nil {
			s.logger.Error("cannot get response inner message", zap.Error(err))
		} else {
			s.logger.Debug("send message", zap.String("message", rmsg.Summary()))
		}
	}
}

// compileHandlerChain sets up all the handlers by loading the handler modules and compiling them in a chain.
func compileHandlerChain(ctx caddy.Context, s *Server) (handlers.Handler, error) {
	handlersRaw, err := ctx.LoadModule(s, "HandlersRaw")
	if err != nil {
		return nil, fmt.Errorf("loading handler modules: %v", err)
	}

	// type-cast the handlers
	var handlersTyped []handlers.Handler
	for _, handler := range handlersRaw.([]any) {
		handlersTyped = append(handlersTyped, handler.(handlers.Handler))
	}

	// create the handler chain
	return handlerChain{handlers: handlersTyped}, nil
}

// handlerChain calls a chain of handlers in reverse order.
type handlerChain struct {
	handlers []handlers.Handler
}

func (c handlerChain) Handle4(req, resp *dhcpv4.DHCPv4, next func() error) error {
	for i := len(c.handlers) - 1; i >= 0; i-- {
		// copy the next handler (it's an interface, so it's just
		// a very lightweight copy of a pointer); this is important
		// because this is a closure to the func below, which
		// re-assigns the value as it compiles the handler chain stack;
		// if we don't make this copy, we'd affect the underlying
		// pointer for all future request (yikes); we could
		// alternatively solve this by moving the func below out of
		// this closure and into a standalone package-level func,
		// but I just thought this made more sense
		nextCopy := next
		next = func() error {
			return c.handlers[i].Handle4(req, resp, nextCopy)
		}
	}
	return next()
}

func (c handlerChain) Handle6(req *dhcpv6.Message, resp dhcpv6.DHCPv6, next func() error) error {
	for i := len(c.handlers) - 1; i >= 0; i-- {
		// copy the next handler (it's an interface, so it's just
		// a very lightweight copy of a pointer); this is important
		// because this is a closure to the func below, which
		// re-assigns the value as it compiles the handler chain stack;
		// if we don't make this copy, we'd affect the underlying
		// pointer for all future request (yikes); we could
		// alternatively solve this by moving the func below out of
		// this closure and into a standalone package-level func,
		// but I just thought this made more sense
		nextCopy := next
		next = func() error { return c.handlers[i].Handle6(req, resp, nextCopy) }
	}
	return next()
}

func parseAddresses(addresses []string) ([]*net.UDPAddr, error) {
	var result []*net.UDPAddr
	for _, address := range addresses {
		var (
			addr *net.UDPAddr
			err  error
		)
		if ip := net.ParseIP(address); ip != nil {
			// if it's just an IP address, assign the port based on the IP address family
			isIPv6 := ip.To4() == nil
			var port int
			if isIPv6 {
				port = dhcpv6.DefaultServerPort
			} else {
				port = dhcpv4.ServerPort
			}
			addr = &net.UDPAddr{
				IP:   ip,
				Port: port,
			}
		} else {
			// parse the entire address
			addr, err = net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, err
			}
			if addr.IP == nil {
				// demand that an IP address is specified so we can differentiate between IPv4 and IPv6
				return nil, fmt.Errorf("only port specified, please also specify an IP address: %s", address)
			}
		}
		result = append(result, addr)
	}
	return result, nil
}

// Interfaces guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)

	_ server4.Printfer = (*dhcpServer)(nil)
	_ server6.Printfer = (*dhcpServer)(nil)

	_ handlers.Handler = (*handlerChain)(nil)
)
