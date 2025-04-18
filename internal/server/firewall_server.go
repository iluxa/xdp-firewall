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

package server

import (
	"context"

	"github.com/iluxa/xdp-firewall/internal/fm"
	"github.com/iluxa/xdp-firewall/pkg/proto"

	"google.golang.org/protobuf/types/known/emptypb"
)

type FirewallServer struct {
	fm *fm.FirewallManager
	proto.UnimplementedFirewallServer
}

func NewFirewallServer(fm *fm.FirewallManager) *FirewallServer {
	return &FirewallServer{fm: fm}
}

func (s *FirewallServer) AddRule(ctx context.Context, rule *proto.Rule) (*emptypb.Empty, error) {
	if err := s.fm.AddRule(rule); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *FirewallServer) DeleteRule(ctx context.Context, rule *proto.Rule) (*emptypb.Empty, error) {
	if err := s.fm.DeleteRule(rule); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (s *FirewallServer) DeleteAllRules(ctx context.Context, empty *emptypb.Empty) (*emptypb.Empty, error) {
	if err := s.fm.FlushRules(); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *FirewallServer) ListRules(ctx context.Context, empty *emptypb.Empty) (*proto.RuleList, error) {
	rules, err := s.fm.ListRules()
	if err != nil {
		return nil, err
	}
	return &proto.RuleList{Rules: rules}, nil
}
