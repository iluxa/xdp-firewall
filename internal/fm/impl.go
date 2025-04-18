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
	"encoding/binary"
	"github.com/iluxa/xdp-firewall/internal/bpf"

	"net"
	"unsafe"

	"github.com/rs/zerolog/log"
)

func cidrToKey(cidr *net.IPNet, id uint32) bpf.FwCidrKey {
	ones, _ := cidr.Mask.Size()
	return bpf.FwCidrKey{
		PrefixLen: uint32(ones) + uint32(unsafe.Sizeof(id)*8),
		Id:        id,
		Addr:      ipToUint32(cidr.IP),
	}
}

func ipToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ipv4)
}

func isDefaultCIDR(cidr *net.IPNet) bool {
	return cidr.String() == "0.0.0.0/0"
}

func cidrToString(cidr *net.IPNet) string {
	if cidr == nil || isDefaultCIDR(cidr) {
		return "any"
	}
	return cidr.String()
}

func protocolToString(proto uint16) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "any"
	}
}

func uint32ToIP(ipUint32 uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipUint32)
	return ip
}

func fwCidrKeyToIPNet(key bpf.FwCidrKey) *net.IPNet {
	ip := uint32ToIP(key.Addr)
	mask := net.CIDRMask(int(key.PrefixLen-32), 32)
	return &net.IPNet{IP: ip, Mask: mask}
}

func findLessSpecificNet(n *net.IPNet, fwCidrs map[bpf.FwCidrKey]bpf.FwCidrValue) (key bpf.FwCidrKey, value bpf.FwCidrValue, ok bool) {
	var lessSpecific *net.IPNet
	var lessSpecificPrefixLen int

	for k, v := range fwCidrs {
		candidate := fwCidrKeyToIPNet(k)
		log.Debug().Msgf("findLessSpecific network: %v candidate: %v", n, candidate)
		if candidate.Contains(n.IP) {
			candidatePrefixLen := int(k.PrefixLen - 32)

			if lessSpecific == nil || (candidatePrefixLen > lessSpecificPrefixLen) {
				lessSpecific = candidate
				lessSpecificPrefixLen = candidatePrefixLen
				key = k
				value = v
				ok = true
			}
		}
	}
	if ok {
		log.Debug().Msgf("findLessSpecific network: %v closest: %v", n, lessSpecific)
	}
	return
}

func findMoreSpecificNet(n *net.IPNet, fwCidrs map[bpf.FwCidrKey]bpf.FwCidrValue) (key bpf.FwCidrKey, value bpf.FwCidrValue, ok bool) {
	var moreSpecific *net.IPNet
	var moreSpecificPrefixLen int

	for k, v := range fwCidrs {
		candidate := fwCidrKeyToIPNet(k)
		log.Debug().Msgf("findMoreSpecific network: %v candidate: %v, contains: %v", n, candidate, n.Contains(candidate.IP))
		if n.Contains(candidate.IP) {
			candidatePrefixLen := int(k.PrefixLen - 32)
			if moreSpecific == nil || (candidatePrefixLen < moreSpecificPrefixLen) {
				moreSpecific = candidate
				moreSpecificPrefixLen = candidatePrefixLen
				key = k
				value = v
				ok = true
				log.Debug().Msgf("findMoreSpecific added candidate: %v prefix: %v", candidate, moreSpecificPrefixLen)
			}
		}
	}

	if ok {
		log.Debug().Msgf("findMoreSpecific network: %v moreSpecific: %v", n, moreSpecific)
	}
	return
}
