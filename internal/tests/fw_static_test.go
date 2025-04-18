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
	"context"
	"testing"

	"github.com/iluxa/xdp-firewall/internal/firewall"
	"github.com/iluxa/xdp-firewall/pkg/proto"

	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestFirewallStatic(t *testing.T) {

	tests := []testSet{
		{
			name: "Common test",
			rules: map[testRule]pktStats{
				{}: {2, 0},
				{
					srcIp:   "192.168.1.1/32",
					dstIp:   "192.168.1.2/32",
					srcPort: 12345,
					dstPort: 80,
					proto:   6,
				}: {1, 0},
				{
					srcIp:   "192.168.1.1/32",
					dstIp:   "192.168.1.2/32",
					srcPort: 12345,
					dstPort: 80,
					proto:   17,
				}: {1, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 1),
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 100),
			},
		},
		{
			name: "All network test",
			rules: map[testRule]pktStats{
				{}: {4, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
				getPacket("10.0.0.1", "192.168.254.2", 12345, 342, 22),
				getPacket("10.8.0.1", "10.10.1.1", 80, 342, 17),
				getPacket("10.8.0.1", "10.10.1.1", 0, 0, 1),
			},
		},

		{
			name: "Depended source networks",
			rules: map[testRule]pktStats{
				{}: {1, 0},
				{
					srcIp: "10.0.0.1/32",
					dstIp: "192.168.1.1/32",
				}: {1, 0},
				{
					srcIp: "10.0.0.0/24",
					dstIp: "192.168.1.1/32",
				}: {1, 0},
				{
					srcIp: "10.0.0.0/16",
					dstIp: "192.168.1.1/32",
				}: {1, 0},
				{
					srcIp: "10.0.0.0/8",
					dstIp: "192.168.1.1/32",
				}: {1, 0},
			},
			packets: [][]byte{
				getPacket("10.0.0.1", "192.168.1.1", 12345, 80, 6),
				getPacket("10.0.0.2", "192.168.1.1", 12345, 80, 6),
				getPacket("10.0.1.2", "192.168.1.1", 12345, 80, 6),
				getPacket("10.1.1.2", "192.168.1.1", 12345, 80, 6),
				getPacket("192.168.2.1", "192.168.1.1", 12345, 80, 6),
			},
		},
		{
			name: "TCP packet",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto: 6,
				}: {1, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},
		{
			name: "UDP packet",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto: 17,
				}: {1, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
			},
		},
		{
			name: "TCP packet filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto: 6,
				}: {1, 0},
				{
					proto: 17,
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},
		{
			name: "UDP packet filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto: 6,
				}: {0, 0},
				{
					proto: 17,
				}: {1, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
			},
		},

		{
			name: "Source port filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					srcPort: 12345,
				}: {2, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
			},
		},

		{
			name: "TCP source port filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto:   6,
					srcPort: 12345,
				}: {1, 0},
				{
					srcPort: 12345,
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},

		{
			name: "UDP source port filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto:   17,
					srcPort: 12345,
				}: {1, 0},
				{
					srcPort: 12345,
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
			},
		},

		{
			name: "Dest port filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					dstPort: 80,
				}: {2, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
			},
		},

		{
			name: "TCP dest port filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto:   6,
					dstPort: 80,
				}: {1, 0},
				{
					dstPort: 80,
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},

		{
			name: "UDP dest port filtered",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					proto:   17,
					dstPort: 80,
				}: {1, 0},
				{
					dstPort: 80,
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 17),
			},
		},

		{
			name: "Priority default src",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					srcIp: "192.168.1.1/32",
				}: {1, 0},
				{
					dstIp: "192.168.1.2/32",
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},
		{
			name: "Priority src",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					srcIp: "192.168.1.1/32",
				}: {1, 0},
				{
					dstIp: "192.168.1.2/32",
					prio:  1,
				}: {0, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},
		{
			name: "Priority dst",
			rules: map[testRule]pktStats{
				{}: {0, 0},
				{
					srcIp: "192.168.1.1/32",
					prio:  1,
				}: {0, 0},
				{
					dstIp: "192.168.1.2/32",
				}: {1, 0},
			},
			packets: [][]byte{
				getPacket("192.168.1.1", "192.168.1.2", 12345, 80, 6),
			},
		},
	}

	if err := setupVethPair(); err != nil {
		t.Fatalf("setupVethPair failed: %v", err)
	}
	defer teardownVethPair()

	fw, err := firewall.NewFirewall(60051)
	if err != nil {
		t.Fatalf("failed to start firewall: %v", err)
	}
	defer func() {
		if err := fw.Stop(); err != nil {
			t.Fatalf("failed to stop firewall: %v", err)
		}
	}()

	err = fw.AttachInterface(veth1, true)
	if err != nil {
		t.Fatalf("failed to attach interface: %v", err)
	}

	conn, err := grpc.NewClient("localhost:60051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := proto.NewFirewallClient(conn)

	handle, err := pcap.OpenLive(veth2, 65535, true, pcap.BlockForever)
	if err != nil {
		t.Fatalf("failed to open pcap handle: %v", err)
	}
	defer handle.Close()

	for _, tst := range tests {
		for rule := range tst.rules {
			_, err = client.AddRule(context.Background(), getRule(t, rule))
			if err != nil {
				t.Fatalf("%q: failed to add rule: %v", tst.name, err)
			}
		}

		for _, pkt := range tst.packets {
			if err := handle.WritePacketData(pkt); err != nil {
				t.Fatalf("%q: failed to write packet: %v", tst.name, err)
			}
		}

		ruleList, err := client.ListRules(context.Background(), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("%q: failed to add rule: %v", tst.name, err)
		}
		for _, ruleOut := range ruleList.Rules {
			testRuleOut, packets, bytes := getRuleOut(t, ruleOut)
			s, ok := tst.rules[testRuleOut]
			if !ok {
				t.Fatalf("%q: rule not found: %v", tst.name, testRuleOut)
			}
			if packets != s.packets {
				t.Fatalf("%q: packets mismatch: expected %d, got %d, rule: %q", tst.name, s.packets, packets, testRuleOut)
			}
			if packets != 0 && s.bytes != 0 && bytes != s.bytes {
				t.Fatalf("%q: bytes mismatch: expected %d, got %d, rule: %q", tst.name, s.bytes, bytes, testRuleOut)
			}
		}

		_, err = client.DeleteAllRules(context.Background(), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("%q: failed to flush rules: %v", tst.name, err)
		}

	}
}
