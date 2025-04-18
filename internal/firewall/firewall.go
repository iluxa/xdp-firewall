/*
 * Copyright (C) 2025 Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package firewall

import (
	"fmt"
	"github.com/iluxa/xdp-firewall/internal/bpf"
	"github.com/iluxa/xdp-firewall/internal/fm"
	"github.com/iluxa/xdp-firewall/internal/server"
	"github.com/iluxa/xdp-firewall/pkg/proto"
	"net"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

type Firewall interface {
	AttachInterface(iface string, isGeneric bool) error
	Stop() error
}

type FirewallImpl struct {
	xdpFirewall     bpf.XdpFirewall
	firewallManager *fm.FirewallManager
	firewallServer  *server.FirewallServer
	grpcServer      *grpc.Server
}

func NewFirewall(grpcPort uint16) (Firewall, error) {
	var err error
	f := FirewallImpl{}

	f.xdpFirewall, err = bpf.NewXdpFirewall()
	if err != nil {
		return nil, fmt.Errorf("failed to create xdp firewall: %w", err)
	}
	f.firewallManager, err = fm.NewFirewallManager(f.xdpFirewall.GetBpfObjects())
	if err != nil {
		return nil, fmt.Errorf("failed to create xdp firewall manager: %w", err)
	}

	f.grpcServer = grpc.NewServer()
	f.firewallServer = server.NewFirewallServer(f.firewallManager)
	proto.RegisterFirewallServer(f.grpcServer, f.firewallServer)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", grpcPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen gRPC port: %w", err)
	}

	go func() {
		if err := f.grpcServer.Serve(listener); err != nil {
			log.Error().Err(err).Msg("failed to serve grpc")
		}
	}()

	return &f, nil
}

func (f *FirewallImpl) AttachInterface(ifaceStr string, isGeneric bool) error {
	iface, err := net.InterfaceByName(ifaceStr)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", ifaceStr, err)
	}
	return f.xdpFirewall.AttachInterface(iface.Index, isGeneric)
}

func (f *FirewallImpl) Stop() error {
	var err error
	log.Debug().Msg("Stopping firewall")

	f.grpcServer.GracefulStop()
	log.Debug().Msg("... grpc server stopped")

	f.firewallManager.Close()
	log.Debug().Msg("... firewall manager closed")

	err = f.xdpFirewall.DetachAllInterfaces()
	if err != nil {
		return fmt.Errorf("failed to detach all interfaces: %w", err)
	}
	log.Debug().Msg("... xdp firewall detached")

	log.Debug().Msg("Firewall stopped")
	return nil
}
