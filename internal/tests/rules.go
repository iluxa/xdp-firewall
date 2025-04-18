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

package tests

import (
	"fmt"
	"net"
	"testing"

	"github.com/iluxa/xdp-firewall/pkg/proto"
)

type testRule struct {
	srcIp   string
	dstIp   string
	srcPort uint16
	dstPort uint16
	proto   uint8
	prio    uint32
	action  proto.Action
}

func (r testRule) String() string {
	return fmt.Sprintf("srcIp: %s, dstIp: %s, srcPort: %d, dstPort: %d, proto: %d, prio: %d action: %d", r.srcIp, r.dstIp, r.srcPort, r.dstPort, r.proto, r.prio, r.action)
}

func getRule(t *testing.T, rule testRule) *proto.Rule {
	var protoSrcCIDR *proto.CIDR
	var protoDstCIDR *proto.CIDR
	var protoIpProto *uint32
	var protoSrcPort *uint32
	var protoDstPort *uint32

	var err error
	var srcCIDR *net.IPNet
	var dstCIDR *net.IPNet

	if rule.srcIp != "" {
		if _, srcCIDR, err = net.ParseCIDR(rule.srcIp); err != nil {
			t.Fatalf("Invalid source CIDR: %s\n", rule.srcIp)
			return nil
		}
		srcOnes, _ := srcCIDR.Mask.Size()
		protoSrcCIDR = &proto.CIDR{Ip: srcCIDR.IP.To4(), Prefix: uint32(srcOnes)}
	}

	if rule.dstIp != "" {
		if _, dstCIDR, err = net.ParseCIDR(rule.dstIp); err != nil {
			t.Fatalf("Invalid source CIDR: %s\n", rule.dstIp)
			return nil
		}
		dstOnes, _ := dstCIDR.Mask.Size()
		protoDstCIDR = &proto.CIDR{Ip: dstCIDR.IP.To4(), Prefix: uint32(dstOnes)}
	}

	if rule.srcPort != 0 {
		p := uint32(rule.srcPort)
		protoSrcPort = &p
	}

	if rule.dstPort != 0 {
		p := uint32(rule.dstPort)
		protoDstPort = &p
	}

	if rule.proto != 0 {
		p := uint32(rule.proto)
		protoIpProto = &p
	}

	return &proto.Rule{
		SrcIp:    protoSrcCIDR,
		DstIp:    protoDstCIDR,
		Protocol: protoIpProto,
		SrcPort:  protoSrcPort,
		DstPort:  protoDstPort,
		Action:   rule.action,
		Priority: rule.prio,
	}
}

func getRuleOut(t *testing.T, rule *proto.RuleOut) (outRule testRule, packets, bytes uint64) {
	var srcIp string
	var dstIp string
	var srcPort uint16
	var dstPort uint16
	var ipProtocol uint8
	var prio uint32
	var action proto.Action

	if rule.Rule.SrcIp != nil {
		srcIp = fmt.Sprintf("%s/%d", net.IP(rule.Rule.SrcIp.Ip).String(), rule.Rule.SrcIp.Prefix)
		if srcIp == "0.0.0.0/0" {
			srcIp = ""
		}
	}

	if rule.Rule.DstIp != nil {
		dstIp = fmt.Sprintf("%s/%d", net.IP(rule.Rule.DstIp.Ip).String(), rule.Rule.DstIp.Prefix)
		if dstIp == "0.0.0.0/0" {
			dstIp = ""
		}
	}

	if rule.Rule.SrcPort != nil {
		srcPort = uint16(*rule.Rule.SrcPort)
	}
	if rule.Rule.DstPort != nil {
		dstPort = uint16(*rule.Rule.DstPort)
	}
	if rule.Rule.Protocol != nil {
		ipProtocol = uint8(*rule.Rule.Protocol)
	}
	action = rule.Rule.Action
	prio = rule.Rule.Priority

	outRule = testRule{
		srcIp:   srcIp,
		dstIp:   dstIp,
		srcPort: srcPort,
		dstPort: dstPort,
		proto:   ipProtocol,
		action:  action,
		prio:    prio,
	}
	packets = rule.Packets
	bytes = rule.Bytes
	return

}
