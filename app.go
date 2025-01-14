package caddydhcp

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
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
	"github.com/lion7/caddydhcp/handlers/searchdomains"
	"github.com/lion7/caddydhcp/handlers/serverid"
	"github.com/lion7/caddydhcp/handlers/sleep"
	"github.com/lion7/caddydhcp/handlers/staticroute"
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
	caddy.RegisterModule(searchdomains.Module{})
	caddy.RegisterModule(serverid.Module{})
	caddy.RegisterModule(sleep.Module{})
	caddy.RegisterModule(staticroute.Module{})
}

type App struct {
	Servers map[string]*Server `json:"servers,omitempty"`

	servers  []*dhcpServer
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
	addresses  []caddy.NetworkAddress
	handler    handlers.Handler
	ctx        caddy.Context
	logger     *zap.Logger
	accessLog  *zap.Logger

	connections []net.PacketConn
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dhcp",
		New: func() caddy.Module { return new(App) },
	}
}

func (app *App) Provision(ctx caddy.Context) error {
	for name, srv := range app.Servers {
		interfaces := srv.Interfaces
		if len(interfaces) == 0 {
			interfaces = []string{""}
		}

		var addresses []caddy.NetworkAddress
		for _, address := range srv.Addresses {
			addr, err := caddy.ParseNetworkAddress(address)
			if err != nil {
				return err
			}
			// todo: set port based on IP family
			addresses = append(addresses, addr)
		}
		if len(addresses) == 0 {
			addresses = append(addresses, caddy.NetworkAddress{
				Network:   "udp4",
				StartPort: dhcpv4.ServerPort,
				EndPort:   dhcpv4.ServerPort,
			})
			addresses = append(addresses, caddy.NetworkAddress{
				Network:   "udp6",
				StartPort: dhcpv6.DefaultServerPort,
				EndPort:   dhcpv6.DefaultServerPort,
			})
			addresses = append(addresses, caddy.NetworkAddress{
				Network:   "udp6",
				Host:      dhcpv6.AllDHCPRelayAgentsAndServers.String(),
				StartPort: dhcpv6.DefaultServerPort,
				EndPort:   dhcpv6.DefaultServerPort,
			})
			addresses = append(addresses, caddy.NetworkAddress{
				Network:   "udp6",
				Host:      dhcpv6.AllDHCPServers.String(),
				StartPort: dhcpv6.DefaultServerPort,
				EndPort:   dhcpv6.DefaultServerPort,
			})
		}

		handler, err := compileHandlerChain(ctx, srv)
		if err != nil {
			return err
		}

		logger := ctx.Logger().Named(name)
		var accessLog *zap.Logger
		if srv.Logs {
			accessLog = logger.Named("access")
		}
		s := &dhcpServer{
			name:       name,
			interfaces: interfaces,
			addresses:  addresses,
			handler:    handler,
			ctx:        ctx,
			logger:     logger,
			accessLog:  accessLog,
		}

		app.servers = append(app.servers, s)
	}
	return nil
}

// Start starts the app.
func (app *App) Start() error {
	app.errGroup = &errgroup.Group{}
	for _, s := range app.servers {
		s.logger.Info(
			"starting server loop",
			zap.String("name", s.name),
			zap.Strings("interfaces", s.interfaces),
			zap.Stringers("addresses", s.addresses),
		)
		for _, addr := range s.addresses {
			ln, err := addr.Listen(s.ctx, 0, net.ListenConfig{})
			if err != nil {
				return fmt.Errorf("failed to listen on %s: %v", addr, err)
			}
			conn := ln.(net.PacketConn)
			s.connections = append(s.connections, conn)
			if addr.Network == "udp6" {
				app.errGroup.Go(func() error {
					defer conn.Close()
					for {
						rbuf := make([]byte, 4096) // FIXME this is bad
						n, peer, err := conn.ReadFrom(rbuf)
						if err != nil {
							s.logger.Error("error reading from packet conn", zap.Error(err))
							return err
						}
						s.logger.Info("handling request", zap.Stringer("peer", peer))

						m, err := dhcpv6.FromBytes(rbuf[:n])
						if err != nil {
							s.logger.Error("error parsing DHCPv6 request", zap.Error(err))
							continue
						}

						upeer, ok := peer.(*net.UDPAddr)
						if !ok {
							s.logger.Warn("not a UDP connection?", zap.Stringer("peer", peer))
							continue
						}

						go s.handle6(conn, upeer, m)
					}
				})
			} else if addr.Network == "udp4" {
				app.errGroup.Go(func() error {
					defer conn.Close()
					for {
						rbuf := make([]byte, 4096) // FIXME this is bad
						n, peer, err := conn.ReadFrom(rbuf)
						if err != nil {
							s.logger.Error("error reading from packet conn", zap.Error(err))
							return err
						}
						s.logger.Info("handling request", zap.Stringer("peer", peer))

						m, err := dhcpv4.FromBytes(rbuf[:n])
						if err != nil {
							s.logger.Error("error parsing DHCPv4 request", zap.Error(err))
							continue
						}

						upeer, ok := peer.(*net.UDPAddr)
						if !ok {
							s.logger.Warn("not a UDP connection?", zap.Stringer("peer", peer))
							continue
						}

						// Set peer to broadcast if the client did not have an IP.
						if upeer.IP == nil || upeer.IP.To4().Equal(net.IPv4zero) {
							upeer = &net.UDPAddr{
								IP:   net.IPv4bcast,
								Port: upeer.Port,
							}
						}

						go s.handle4(conn, upeer, m)
					}
				})
			}
		}
	}
	return nil
}

// Stop stops the app.
func (app *App) Stop() error {
	for _, s := range app.servers {
		s.logger.Info(
			"server shutting down with eternal grace period",
			zap.String("name", s.name),
			zap.Strings("interfaces", s.interfaces),
			zap.Stringers("addresses", s.addresses),
		)
		for _, conn := range s.connections {
			_ = conn.Close()
			if err := conn.Close(); err != nil {
				return err
			}
		}
	}
	return app.errGroup.Wait()
}

func (s *dhcpServer) handle4(conn net.PacketConn, peer *net.UDPAddr, m *dhcpv4.DHCPv4) {
	var (
		req, resp *dhcpv4.DHCPv4
		err       error
		n         int
	)

	if s.accessLog != nil {
		start := time.Now()
		defer func() {
			end := time.Now()
			d := end.Sub(start)
			s.accessLog.Info(
				"handled request",
				zap.String("remote_ip", peer.IP.String()),
				zap.Int("remote_port", peer.Port),
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
		s.logger.Error("failed to build reply", zap.Error(err))
		return
	}
	switch mt := req.MessageType(); mt {
	case dhcpv4.MessageTypeDiscover:
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	case dhcpv4.MessageTypeRequest:
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	default:
		s.logger.Error("unhandled message type", zap.Stringer("messageType", mt))
		return
	}

	err = s.handler.Handle4(handlers.DHCPv4{DHCPv4: req}, handlers.DHCPv4{DHCPv4: resp}, func() error { return nil })
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

func (s *dhcpServer) handle6(conn net.PacketConn, peer *net.UDPAddr, m dhcpv6.DHCPv6) {
	var (
		req, resp *dhcpv6.Message
		err       error
		n         int
	)

	if s.accessLog != nil {
		start := time.Now()
		defer func() {
			end := time.Now()
			d := end.Sub(start)
			s.accessLog.Info(
				"handled request",
				zap.String("remote_ip", peer.IP.String()),
				zap.Int("remote_port", peer.Port),
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

	err = s.handler.Handle6(handlers.DHCPv6{Message: req}, handlers.DHCPv6{Message: resp}, func() error { return nil })
	if err != nil {
		s.logger.Error("handler chain failed", zap.Error(err))
		return
	}

	if resp != nil {
		if m.IsRelay() {
			// if the request was relayed, re-encapsulate the response
			var encapsulated dhcpv6.DHCPv6
			encapsulated, err = dhcpv6.NewRelayReplFromRelayForw(m.(*dhcpv6.RelayMessage), resp)
			if err != nil {
				s.logger.Error("cannot create relay-repl from relay-forw", zap.Error(err))
				return
			}
			n, err = conn.WriteTo(encapsulated.ToBytes(), peer)
		} else {
			n, err = conn.WriteTo(resp.ToBytes(), peer)
		}
		if err != nil {
			s.logger.Error("cannot write response", zap.Error(err))
		}
		s.logger.Debug("send message", zap.String("message", resp.Summary()))
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

func (c handlerChain) Handle4(req, resp handlers.DHCPv4, next func() error) error {
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

func (c handlerChain) Handle6(req, resp handlers.DHCPv6, next func() error) error {
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

// Interfaces guards
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)

	_ handlers.Handler = (*handlerChain)(nil)
)
