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

package fm

import (
	"github.com/iluxa/xdp-firewall/internal/bpf"
	"net"
	"sync"

	"github.com/iluxa/xdp-firewall/pkg/proto"
)

const (
	ACTION_ALLOW = 0
	ACTION_DENY  = 1
	MAX_ENTRIES  = 1000
)

type CIDRKey struct {
	PrefixLen uint32
	Id        uint32
	Addr      uint32
}

type FirewallRule struct {
	SrcCIDR  *net.IPNet
	DstCIDR  *net.IPNet
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
	Action   uint8
	Priority uint32
}

type RuleIdentifier struct {
	SrcCIDR  string
	DstCIDR  string
	Protocol string
	SrcPort  uint32
	DstPort  uint32
}

type FirewallManager struct {
	bpfObjs  bpf.FwObjects
	ruleDB   map[uint32]*proto.Rule
	rulesMtx sync.Mutex
}

type RuleAttrs struct {
	Action   uint8
	Priority uint32
}

func NewFirewallManager(bpfObjs bpf.FwObjects) (*FirewallManager, error) {
	return &FirewallManager{
		bpfObjs: bpfObjs,
		ruleDB:  make(map[uint32]*proto.Rule),
	}, nil
}

func (fm *FirewallManager) Close() {
	// firewall manager manipulates eBPF maps only,
	// maps are cleared in the kernel on application exit
}
