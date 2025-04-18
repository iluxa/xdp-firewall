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

	"github.com/vishvananda/netlink"
)

const (
	veth1 = "fw_test_veth1"
	veth2 = "fw_test_veth2"
)

func setupVethPair() error {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = veth1
	veth := &netlink.Veth{
		LinkAttrs: linkAttrs,
		PeerName:  veth2,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("failed to set %s up: %v", veth1, err)
	}

	peer, err := netlink.LinkByName(veth2)
	if err != nil {
		return fmt.Errorf("failed to get peer link: %v", err)
	}

	if err := netlink.LinkSetUp(peer); err != nil {
		return fmt.Errorf("failed to set %s up: %v", veth2, err)
	}

	return nil
}

func teardownVethPair() {
	link, err := netlink.LinkByName(veth1)
	if err == nil {
		netlink.LinkDel(link)
	}
}

type pktStats struct {
	packets uint64
	bytes   uint64
}

type testSet struct {
	name   string
	rules   map[testRule]pktStats
	packets [][]byte
}

