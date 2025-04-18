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

package bpf

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cflags "-O2 -g -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu" Fw bpf.c

type XdpFirewall interface {
	GetBpfObjects() FwObjects
	AttachInterface(interfaceIndex int, isGeneric bool) error
	DetachInterface(interfaceIndex int) error
	DetachAllInterfaces() error
}

const xdpFlagGeneric = 0x2
const xdpFlagDriver = 0x4

type linkMode struct {
	link.Link
	mode link.XDPAttachFlags
}

type netlinkMode struct {
	netlink.Link
	mode int
}

func NewXdpFirewall() (XdpFirewall, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	objs := XdpFirewallImpl{
		xdpLinks: make(map[int]linkMode),
		netLinks: make(map[int]netlinkMode),
	}
	if err := objs.loadBpfObjects(""); err != nil {
		return nil, fmt.Errorf("load objects failed: %w", err)
	}

	return &objs, nil
}

func (f *XdpFirewallImpl) AttachInterface(interfaceIndex int, isGeneric bool) error {

	var kernelVersion *kernel.VersionInfo
	kernelVersion, err := kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("detect kernel version failed: %w", err)
	}

	//TODO: consider detaching interface if already attached

	if kernel.CompareKernelVersion(*kernelVersion, kernel.VersionInfo{Kernel: 5, Major: 7, Minor: 0}) < 1 {
		attachMode := xdpFlagDriver
		if isGeneric {
			attachMode = xdpFlagGeneric
		}

		lnk, err := netlink.LinkByIndex(interfaceIndex)
		if err != nil {
			return fmt.Errorf("find network link %v failed: %w", interfaceIndex, err)
		}

		err = netlink.LinkSetXdpFdWithFlags(lnk, f.bpfObjs.Fw.FD(), attachMode)
		if err != nil {
			return fmt.Errorf("could not set XDP program: %w", err)
		}

		f.netLinks[interfaceIndex] = netlinkMode{Link: lnk, mode: attachMode}
	} else {
		attachMode := link.XDPDriverMode
		if isGeneric {
			attachMode = link.XDPGenericMode
		}

		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   f.bpfObjs.Fw,
			Interface: interfaceIndex,
			Flags:     attachMode,
		})
		if err != nil {
			return fmt.Errorf("could not attach XDP program: %w", err)
		}

		f.xdpLinks[interfaceIndex] = linkMode{Link: lnk, mode: attachMode}
	}

	return nil
}

func (f *XdpFirewallImpl) DetachInterface(interfaceIndex int) error {
	link, ok := f.xdpLinks[interfaceIndex]
	if ok {
		if err := link.Close(); err != nil {
			return fmt.Errorf("could not close XDP program: %w", err)
		}
		delete(f.xdpLinks, interfaceIndex)
	}

	l, ok := f.netLinks[interfaceIndex]
	if ok {
		err := netlink.LinkSetXdpFdWithFlags(l, -1, l.mode)
		if err != nil {
			return fmt.Errorf("could not detach XDP program: %w", err)
		}

		delete(f.netLinks, interfaceIndex)
	}

	return nil
}

func (f *XdpFirewallImpl) DetachAllInterfaces() error {
	for interfaceIndex, link := range f.xdpLinks {
		if err := link.Close(); err != nil {
			return fmt.Errorf("could not close XDP program from interface %d: %w", interfaceIndex, err)
		}
		delete(f.xdpLinks, interfaceIndex)
	}
	f.xdpLinks = make(map[int]linkMode)

	for interfaceIndex, link := range f.netLinks {
		err := netlink.LinkSetXdpFdWithFlags(link, -1, link.mode)
		if err != nil {
			return fmt.Errorf("could not detach XDP program: %w", err)
		}

		delete(f.netLinks, interfaceIndex)
	}
	f.netLinks = make(map[int]netlinkMode)

	return nil
}

func (f *XdpFirewallImpl) GetBpfObjects() FwObjects {
	return f.bpfObjs
}

type XdpFirewallImpl struct {
	bpfObjs  FwObjects
	specs    *ebpf.CollectionSpec
	xdpLinks map[int]linkMode
	netLinks map[int]netlinkMode
}

func (objs *XdpFirewallImpl) loadBpfObjects(bpfPath string) error {
	var err error
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfPath,
		},
		Programs: ebpf.ProgramOptions{},
	}

	reader := bytes.NewReader(_FwBytes)
	objs.specs, err = ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return err
	}

	err = objs.specs.LoadAndAssign(&objs.bpfObjs, &opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Got verifier error : %+v", ve)
		}
	}
	return err
}
