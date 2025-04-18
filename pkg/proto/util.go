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

package proto

import (
	"fmt"
	"net"
)

func (r *Rule) ToString() string {
	return fmt.Sprintf("%s:%d %s:%d proto: %d action: %d", r.SrcIp.toIPNet().String(), *r.SrcPort, r.DstIp.toIPNet().String(), *r.DstPort, *r.Protocol, r.Action)
}

func (x *CIDR) toIPNet() *net.IPNet {
	ip := net.IP(x.Ip)

	mask := net.CIDRMask(int(x.Prefix), 8*len(ip))

	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}
