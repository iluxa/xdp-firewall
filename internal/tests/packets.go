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
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packetKey struct {
	srcIp   string
	dstIp   string
	srcPort uint16
	dstPort uint16
	proto   uint8
}

var packets = make(map[packetKey][]byte)

func getPacket(srcIp, dstIp string, srcPort, dstPort uint16, proto uint8) []byte {
	pk := packetKey{srcIp, dstIp, srcPort, dstPort, proto}
	if pkt, ok := packets[pk]; ok {
		return pkt
	}
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIp),
		DstIP:    net.ParseIP(dstIp),
		Protocol: layers.IPProtocol(proto),
		Version:  4,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
	}
	gopacket.SerializeLayers(buffer, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload([]byte("test payload")))
	packets[pk] = buffer.Bytes()

	return packets[pk]
}
