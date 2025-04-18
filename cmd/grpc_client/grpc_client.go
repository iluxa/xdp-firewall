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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/iluxa/xdp-firewall/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	ACTION_ALLOW = 0
	ACTION_DENY  = 1
	MAX_ENTRIES  = 1000
)

func main() {
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)
	addSrc := addCmd.String("src", "0.0.0.0/0", "Source CIDR")
	addDst := addCmd.String("dst", "0.0.0.0/0", "Destination CIDR")
	addProto := addCmd.String("proto", "any", "Protocol (tcp/udp/any)")
	addSport := addCmd.Int("sport", 0, "Source port (0 for any)")
	addDport := addCmd.Int("dport", 0, "Destination port (0 for any)")
	addAction := addCmd.String("action", "", "Action (accept/drop)")
	addPriority := addCmd.Int("priority", 0, "Rule priority")

	delCmd := flag.NewFlagSet("del", flag.ExitOnError)
	delSrc := delCmd.String("src", "0.0.0.0/0", "Source CIDR")
	delDst := delCmd.String("dst", "0.0.0.0/0", "Destination CIDR")
	delProto := delCmd.String("proto", "any", "Protocol (tcp/udp/any)")
	delSport := delCmd.Int("sport", 0, "Source port")
	delDport := delCmd.Int("dport", 0, "Destination port")

	if len(os.Args) < 2 {
		fmt.Println("Usage: firewall [-g gRPCPort] <add|del|list> [options]")
		os.Exit(1)
	}

	os.Args = os.Args[1:]

	grpcPort := uint16(60051)
	if os.Args[0] == "-g" {
		if len(os.Args) < 2 {
			fmt.Println("Usage: firewall [-g gRPCPort] <add|del|list> [options]")
			os.Exit(1)
		}
		var err error
		var port int
		if port, err = strconv.Atoi(os.Args[1]); err != nil {
			fmt.Println("Invalid gRPC port:", err)
			os.Exit(1)
		}
		grpcPort = uint16(port)
		os.Args = os.Args[2:]
	}

	conn, err := grpc.NewClient(fmt.Sprintf("localhost:%v", grpcPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("failed to connect to gRPC server: %v", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := proto.NewFirewallClient(conn)

	if len(os.Args) < 1 {
		fmt.Println("Usage: firewall [-g gRPCPort] <add|del|list> [options]")
		os.Exit(1)
	}

	switch os.Args[0] {
	case "add":
		addCmd.Parse(os.Args[1:])
		rule, err := parseRule(
			*addSrc,
			*addDst,
			*addProto,
			uint16(*addSport),
			uint16(*addDport),
			*addAction,
			uint32(*addPriority),
		)
		if err != nil {
			log.Fatal("Invalid add rule:", err)
		}

		_, err = client.AddRule(context.Background(), rule)
		if err != nil {
			log.Fatal("Failed to add rule:", err)
		}

		fmt.Println("Rule added successfully")

	case "del":
		delCmd.Parse(os.Args[1:])
		rule, err := parseRule(
			*delSrc,
			*delDst,
			*delProto,
			uint16(*delSport),
			uint16(*delDport),
			"", // Action is not required for delete
			0,  // Priority is not required for delete
		)
		if err != nil {
			log.Fatal("Invalid del rule:", err)
		}
		if _, err := client.DeleteRule(context.Background(), rule); err != nil {
			log.Fatal("Delete rule failed:", err)
		}
		fmt.Println("Rule deleted successfully")

	case "list":
		ruleList, err := client.ListRules(context.Background(), &emptypb.Empty{})
		if err != nil {
			log.Fatal("List rules failed:", err)
		}

		printRules(ruleList)

	default:
		fmt.Printf("Unknown command %q. Use 'add', 'del', or 'list'.", os.Args[0])
	}
}

func printRules(ruleList *proto.RuleList) {
	fmt.Printf("%-18s %-18s %-8s %-10s %-10s %-8s %-8s %-7v %-7v\n",
		"Source", "Destination", "Proto", "Sport", "Dport", "Action", "Priority", "Packets", "Bytes")

	var lines []string
	for _, r := range ruleList.Rules {
		l := fmt.Sprintf("%-18s %-18s %-8s %-10s %-10s %-8s %-8d %-7v %-7v\n",
			cidrToString(r.Rule.SrcIp),
			cidrToString(r.Rule.DstIp),
			protocolToString(r.Rule.Protocol),
			portToString(r.Rule.SrcPort),
			portToString(r.Rule.DstPort),
			actionToString(r.Rule.Action),
			r.Rule.Priority,
			r.Packets, r.Bytes,
		)
		lines = append(lines, l)
	}
	sort.Slice(lines, func(i, j int) bool {
		return lines[i] < lines[j]
	})
	for _, l := range lines {
		fmt.Print(l)
	}
}

func cidrToString(cidr *proto.CIDR) string {
	if cidr == nil {
		return "0.0.0.0/0"
	}
	return fmt.Sprintf("%s/%d", net.IP(cidr.Ip), cidr.Prefix)
}

func protocolToString(proto *uint32) string {
	if proto == nil {
		return "any"
	}
	switch *proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "any"
	}
}

func portToString(port *uint32) string {
	if port == nil {
		return "any"
	}
	return fmt.Sprintf("%d", *port)
}

func actionToString(action proto.Action) string {
	switch action {
	case ACTION_ALLOW:
		return "accept"
	case ACTION_DENY:
		return "drop"
	default:
		return "UNKNOWN"
	}
}

func parseRule(src, dst, ipProto string, sport, dport uint16, action string, prio uint32) (*proto.Rule, error) {
	rule := proto.Rule{}

	var err error
	rule.SrcIp, err = parseCIDR(src)
	if err != nil {
		return nil, err
	}
	rule.DstIp, err = parseCIDR(dst)
	if err != nil {
		return nil, err
	}

	ipProtocol, err := parseProto(ipProto)
	if err != nil {
		return nil, err
	}
	pr := uint32(ipProtocol)
	if pr != 0 {
		rule.Protocol = &pr
	}

	sp := uint32(sport)
	dp := uint32(dport)
	if sp != 0 {
		rule.SrcPort = &sp
	}
	if dp != 0 {
		rule.DstPort = &dp
	}

	if action != "" {
		switch strings.ToLower(action) {
		case "accept":
			rule.Action = ACTION_ALLOW
		case "drop":
			rule.Action = ACTION_DENY
		default:
			return nil, errors.New("invalid action")
		}
	}

	rule.Priority = prio

	return &rule, nil
}

func parseCIDR(cidr string) (*proto.CIDR, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, _ := ipnet.Mask.Size()
	return &proto.CIDR{Ip: ipnet.IP.To4(), Prefix: uint32(ones)}, nil
}

func parseProto(proto string) (uint16, error) {
	switch strings.ToLower(proto) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "any":
		return 0, nil
	default:
		return 0, errors.New("invalid protocol")
	}
}
