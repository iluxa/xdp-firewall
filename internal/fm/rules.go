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
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/iluxa/xdp-firewall/internal/bpf"
	"github.com/iluxa/xdp-firewall/pkg/proto"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

var (
	GlobID     = uint32(1)
	GlobRuleID = uint32(1)
)

func getRuleFields(rule *proto.Rule) (srcCIDR, dstCIDR *net.IPNet, ipProtocol uint16, srcPort, dstPort uint32) {
	allnetCIDR := &net.IPNet{
		IP:   []byte{0, 0, 0, 0},
		Mask: net.CIDRMask(0, 32),
	}

	srcCIDR = allnetCIDR
	dstCIDR = allnetCIDR
	ipProtocol = uint16(0xFFFF)
	srcPort = uint32(0xFFFFFFFF)
	dstPort = uint32(0xFFFFFFFF)

	if rule.SrcIp != nil {
		srcCIDR = &net.IPNet{IP: rule.SrcIp.Ip, Mask: net.CIDRMask(int(rule.SrcIp.Prefix), 32)}
	}
	if rule.DstIp != nil {
		dstCIDR = &net.IPNet{IP: rule.DstIp.Ip, Mask: net.CIDRMask(int(rule.DstIp.Prefix), 32)}
	}
	if rule.Protocol != nil {
		ipProtocol = uint16(*rule.Protocol)
	}
	if rule.SrcPort != nil {
		srcPort = *rule.SrcPort
	}
	if rule.DstPort != nil {
		dstPort = *rule.DstPort
	}
	return
}

func (fm *FirewallManager) AddRule(rule *proto.Rule) error {
	fm.rulesMtx.Lock()
	defer fm.rulesMtx.Unlock()
	var err error
	srcMap := fm.bpfObjs.SrcCidrMap
	dstMap := fm.bpfObjs.DstCidrMap

	srcCIDR, dstCIDR, _, _, _ := getRuleFields(rule)

	var srcLpmId uint32
	var dstLpmId uint32

	// Add rule starting from source CIDR

	log.Trace().Msg("src first add lpm")
	srcLpmId, err = addLpm(srcMap, srcCIDR, 0)
	if err != nil {
		return fmt.Errorf("failed to update src_cidr_map: %w", err)
	}
	log.Debug().Msgf("added src lpm: %v -> %v", srcCIDR, srcLpmId)

	log.Trace().Msg("src second add lpm")
	dstLpmId, err = addLpm(dstMap, dstCIDR, srcLpmId)
	if err != nil {
		return fmt.Errorf("failed to update dst_cidr_map: %w", err)
	}
	log.Debug().Msgf("added dst lpm: %v,%v -> %v", dstCIDR, srcLpmId, dstLpmId)

	log.Trace().Msg("src add rule")
	if err = fm.addProtoPorts(dstLpmId, rule); err != nil {
		return err
	}

	// Add rule starting from dest CIDR

	log.Debug().Msg("dst first add lpm")
	dstLpmId, err = addLpm(dstMap, dstCIDR, 0)
	if err != nil {
		return fmt.Errorf("failed to update dst_cidr_map: %w", err)
	}
	log.Debug().Msgf("added dst lpm: %v -> %v", dstCIDR, dstLpmId)

	log.Debug().Msg("dst second add lpm")
	srcLpmId, err = addLpm(srcMap, srcCIDR, dstLpmId)
	if err != nil {
		return fmt.Errorf("failed to update src_cidr_map: %w", err)
	}
	log.Debug().Msgf("added src lpm: %v,%v -> %v", srcCIDR, dstLpmId, srcLpmId)

	log.Trace().Msg("dst add rule")
	if err = fm.addProtoPorts(srcLpmId, rule); err != nil {
		return err
	}

	return nil
}

func addLpm(m *ebpf.Map, n *net.IPNet, id uint32) (uint32, error) {
	var err error
	lpmKey := cidrToKey(n, id)

	cidrMap := make(map[bpf.FwCidrKey]bpf.FwCidrValue)
	it := m.Iterate()
	var k bpf.FwCidrKey
	var v bpf.FwCidrValue
	for it.Next(&k, &v) {
		if k == lpmKey {
			return v.InnerId, nil
		}
		if k.Id == id {
			cidrMap[k] = v
		}
	}

	lpmValue := bpf.FwCidrValue{
		InnerId: GlobID,
	}
	GlobID++

	if id == 0 {
		moreSpecificKey, moreSpecificValue, ok := findMoreSpecificNet(n, cidrMap)
		if ok {
			log.Debug().Msgf("Adding more specific: %v key: %v\n", moreSpecificKey.String(), lpmKey.String())
			lpmValue.NextCidr = moreSpecificValue.NextCidr
			moreSpecificValue.NextCidr = lpmKey
			if err := m.Update(&moreSpecificKey, &moreSpecificValue, ebpf.UpdateExist); err != nil {
				return 0, err
			}
		} else {
			lessSpecificKey, _, ok := findLessSpecificNet(n, cidrMap)
			if ok {
				log.Debug().Msgf("Adding less specific: %v key: %v\n", lessSpecificKey.String(), lpmKey.String())
				lpmValue.NextCidr = lessSpecificKey
			}
		}
	}

	if err = m.Update(&lpmKey, &lpmValue, ebpf.UpdateNoExist); err != nil {
		err = fmt.Errorf("create new lpm rule failed: %w", err)
	}
	log.Trace().Msgf("add lpm key: %v value: %v", lpmKey, lpmValue.InnerId)
	return lpmValue.InnerId, err
}

func (fm *FirewallManager) addProtoPorts(targetId uint32, rule *proto.Rule) error {
	protoMap := fm.bpfObjs.ProtoMap
	srcPortMap := fm.bpfObjs.SrcPortMap
	dstPortMap := fm.bpfObjs.DstPortMap
	statsMap := fm.bpfObjs.Stats

	_, _, ipProtocol, srcPort, dstPort := getRuleFields(rule)

	var err error
	protocolKey := bpf.FwProtoKey{
		Id:    targetId,
		Proto: ipProtocol,
	}
	var protocolId uint32
	err = protoMap.Lookup(&protocolKey, &protocolId)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		protocolId = GlobID
		GlobID++
		err = protoMap.Update(&protocolKey, &protocolId, ebpf.UpdateNoExist)
	}
	if err != nil {
		return fmt.Errorf("failed to update proto_map: %w", err)
	}
	log.Debug().Msgf("added proto key: (%v) value: %v", protocolKey.String(), protocolId)

	srcPortKey := bpf.FwPortKey{
		Id:   protocolId,
		Port: srcPort,
	}
	var srcPortId uint32
	err = srcPortMap.Lookup(&srcPortKey, &srcPortId)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		srcPortId = GlobID
		GlobID++
		err = srcPortMap.Update(&srcPortKey, &srcPortId, ebpf.UpdateNoExist)
	}
	if err != nil {
		return fmt.Errorf("failed to update src_port_map: %w", err)
	}
	log.Debug().Msgf("added src port key: (%v) value: %v", srcPortKey.String(), srcPortId)

	dstPortKey := bpf.FwPortKey{
		Id:   srcPortId,
		Port: dstPort,
	}
	ruleAttrs := bpf.FwRuleAttrs{
		Action:   uint32(rule.Action),
		Priority: rule.Priority,
		Id:       0,
	}
	err = dstPortMap.Lookup(&dstPortKey, &ruleAttrs)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed to locate dst_port_map: %w", err)
	} else if err == nil {
		return fmt.Errorf("rule already exists")
	}

	ruleAttrs.Id = GlobRuleID
	GlobRuleID++
	if err = dstPortMap.Update(&dstPortKey, &ruleAttrs, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("failed to update dst_port_map: %w", err)
	}
	allStats := make([]bpf.FwPktStats, runtime.NumCPU())
	if err = statsMap.Update(&ruleAttrs.Id, allStats[:], ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("failed to update stats_map: %w", err)
	}
	log.Debug().Msgf("added dst port key: (%v) value: (%v)", dstPortKey.String(), ruleAttrs.String())

	fm.ruleDB[ruleAttrs.Id] = rule
	log.Debug().Msgf("added dstPortMap %v", ruleAttrs.String())

	return nil
}

type RulesDeleter struct {
	srcMap     *ebpf.Map
	dstMap     *ebpf.Map
	protoMap   *ebpf.Map
	srcPortMap *ebpf.Map
	dstPortMap *ebpf.Map
	srcCIDR    *net.IPNet
	dstCIDR    *net.IPNet
	ipProtocol uint16
	srcPort    uint32
	dstPort    uint32
	ruleDB     map[uint32]*proto.Rule
}

func (fm *FirewallManager) DeleteRule(rule *proto.Rule) error {
	fm.rulesMtx.Lock()
	defer fm.rulesMtx.Unlock()

	srcMap := fm.bpfObjs.SrcCidrMap
	dstMap := fm.bpfObjs.DstCidrMap
	protoMap := fm.bpfObjs.ProtoMap
	srcPortMap := fm.bpfObjs.SrcPortMap
	dstPortMap := fm.bpfObjs.DstPortMap

	srcCIDR, dstCIDR, ipProtocol, srcPort, dstPort := getRuleFields(rule)
	var err error

	deleterSrc := &RulesDeleter{
		srcMap:     srcMap,
		dstMap:     dstMap,
		protoMap:   protoMap,
		srcPortMap: srcPortMap,
		dstPortMap: dstPortMap,
		srcCIDR:    srcCIDR,
		dstCIDR:    dstCIDR,
		ipProtocol: ipProtocol,
		srcPort:    srcPort,
		dstPort:    dstPort,
		ruleDB:     fm.ruleDB,
	}

	_, err = deleterSrc.delete(0)
	if err != nil {
		return fmt.Errorf("failed to delete src_ip: %w", err)
	}

	deleterDst := &RulesDeleter{
		srcMap:     dstMap,
		dstMap:     srcMap,
		protoMap:   protoMap,
		srcPortMap: srcPortMap,
		dstPortMap: dstPortMap,
		srcCIDR:    dstCIDR,
		dstCIDR:    srcCIDR,
		ipProtocol: ipProtocol,
		srcPort:    srcPort,
		dstPort:    dstPort,
		ruleDB:     fm.ruleDB,
	}

	_, err = deleterDst.delete(0)
	if err != nil {
		return fmt.Errorf("failed to delete dst_ip: %w", err)
	}

	return nil
}

func clearMap[KEY any, VALUE any](m *ebpf.Map, key KEY, value VALUE) error {
	if m == nil {
		return nil
	}

	iter := m.Iterate()

	for iter.Next(&key, &value) {
		if err := m.Delete(key); err != nil {
			return fmt.Errorf("failed to delete key %+v: %w", key, err)
		}
	}

	return iter.Err()
}

func (fm *FirewallManager) FlushRules() error {
	fm.rulesMtx.Lock()
	defer fm.rulesMtx.Unlock()

	srcMap := fm.bpfObjs.SrcCidrMap
	dstMap := fm.bpfObjs.DstCidrMap
	protoMap := fm.bpfObjs.ProtoMap
	srcPortMap := fm.bpfObjs.SrcPortMap
	dstPortMap := fm.bpfObjs.DstPortMap

	if err := clearMap(srcMap, bpf.FwCidrKey{}, bpf.FwCidrValue{}); err != nil {
		return fmt.Errorf("failed to clear src_cidr_map: %w", err)
	}

	if err := clearMap(dstMap, bpf.FwCidrKey{}, bpf.FwCidrValue{}); err != nil {
		return fmt.Errorf("failed to clear dst_cidr_map: %w", err)
	}

	if err := clearMap(protoMap, bpf.FwProtoKey{}, uint32(0)); err != nil {
		return fmt.Errorf("failed to clear proto_map: %w", err)
	}

	if err := clearMap(srcPortMap, bpf.FwPortKey{}, uint32(0)); err != nil {
		return fmt.Errorf("failed to clear src_port_map: %w", err)
	}

	if err := clearMap(dstPortMap, bpf.FwPortKey{}, bpf.FwRuleAttrs{}); err != nil {
		return fmt.Errorf("failed to clear dst_port_map: %w", err)
	}

	fm.ruleDB = make(map[uint32]*proto.Rule)

	return nil
}

func (d *RulesDeleter) deleteDstPort(dstPortId uint32) (ok bool, err error) {
	dstPortKey := bpf.FwPortKey{
		Id:   dstPortId,
		Port: d.dstPort,
	}

	var ruleAttrs bpf.FwRuleAttrs

	if err = d.dstPortMap.Lookup(&dstPortKey, &ruleAttrs); err != nil {
		return false, fmt.Errorf("failed to lookup dst_port_map: %w", err)
	}
	if err = d.dstPortMap.Delete(dstPortKey); err != nil {
		return false, fmt.Errorf("failed to delete dst_port_map: %w", err)
	}
	delete(d.ruleDB, ruleAttrs.Id)
	log.Debug().Msgf("Deleted dstPortMap k: %v rule: %v", dstPortKey.String(), ruleAttrs.String())

	// Clean up all records if no other with id:
	var k bpf.FwPortKey
	var v bpf.FwRuleAttrs
	it := d.dstPortMap.Iterate()
	for it.Next(&k, &v) {
		if k.Id == dstPortId {
			return false, nil
		}
	}

	log.Debug().Msgf("dstPortMap is empty for id %v", dstPortId)

	return true, nil
}

func (d *RulesDeleter) deleteSrcPort(protoId uint32) (ok bool, err error) {
	k := bpf.FwPortKey{
		Id:   protoId,
		Port: d.srcPort,
	}
	var v uint32

	if err = d.srcPortMap.Lookup(&k, &v); err != nil {
		return false, fmt.Errorf("failed to lookup src_port_map: %w", err)
	}

	if ok, err = d.deleteDstPort(v); err != nil {
		return false, fmt.Errorf("failed to delete dst_port_map: %w", err)
	}

	if !ok {
		return false, nil
	}

	if err = d.srcPortMap.Delete(k); err != nil {
		return false, fmt.Errorf("failed to delete src_port_map: %w", err)
	}

	// Clean up all records if no other with id:
	it := d.srcPortMap.Iterate()
	for it.Next(&k, &v) {
		if k.Id == protoId {
			return false, nil
		}
	}

	log.Debug().Msgf("srcPortMap is empty for id %v", protoId)

	return true, nil
}

func (d *RulesDeleter) deleteProto(id uint32) (ok bool, err error) {
	k := bpf.FwProtoKey{
		Id:    id,
		Proto: d.ipProtocol,
	}
	var v uint32

	if err = d.protoMap.Lookup(&k, &v); err != nil {
		return false, fmt.Errorf("failed to lookup proto_map: %w", err)
	}

	if ok, err = d.deleteSrcPort(v); err != nil {
		return false, fmt.Errorf("failed to delete src_port_map: %w", err)
	}

	if !ok {
		return false, nil
	}

	if err = d.protoMap.Delete(k); err != nil {
		return false, fmt.Errorf("failed to delete proto_map: %w", err)
	}

	it := d.protoMap.Iterate()
	for it.Next(&k, &v) {
		if k.Id == id {
			return false, nil
		}
	}

	log.Debug().Msgf("protoMap is empty for id %v", id)

	return true, nil
}

func (d *RulesDeleter) deleteDstIp(id uint32) (ok bool, err error) {
	lpmKey := cidrToKey(d.dstCIDR, id)
	it := d.dstMap.Iterate()
	var k bpf.FwCidrKey
	var v bpf.FwCidrValue
	var found bool
	for it.Next(&k, &v) {
		if k == lpmKey {
			log.Debug().Msgf("Deleting protoMap %v", v.String())
			if ok, err = d.deleteProto(v.InnerId); err != nil {
				return false, fmt.Errorf("failed to delete proto: %w", err)
			}
			found = true
		}
	}

	if !found {
		return false, fmt.Errorf("dst ip not found")
	}
	if !ok {
		return false, nil
	}

	if err = d.dstMap.Delete(lpmKey); err != nil {
		return false, fmt.Errorf("failed to delete dst_cidr_map: %w", err)
	}

	for it.Next(&k, &v) {
		if k.Id == id {
			return false, nil
		}
	}

	log.Debug().Msgf("dstMap is empty with id %v", id)
	return true, nil
}

func (d *RulesDeleter) delete(id uint32) (ok bool, err error) {
	lpmKey := cidrToKey(d.srcCIDR, id)
	it := d.srcMap.Iterate()
	var k bpf.FwCidrKey
	var v bpf.FwCidrValue
	var lpmValue bpf.FwCidrValue
	var found bool
	for it.Next(&k, &v) {
		if k == lpmKey {
			if ok, err = d.deleteDstIp(v.InnerId); err != nil {
				return false, fmt.Errorf("failed to delete secondary ip: %w", err)
			}
			log.Debug().Msgf("Deleted dstMap %v->%v, ok: %v", k.String(), v.String(), ok)
			found = true
			lpmValue = v
			break
		}
	}
	if !found {
		return false, fmt.Errorf("primary ip not found for id %v", id)
	}
	if !ok {
		return false, nil
	}

	found = false

	it = d.srcMap.Iterate()
	for it.Next(&k, &v) {
		if k.Addr == lpmKey.Addr && k.PrefixLen == lpmKey.PrefixLen {
			found = true
		}
		if v.NextCidr == lpmKey {
			v.NextCidr = lpmValue.NextCidr
			if err := d.srcMap.Update(k, v, ebpf.UpdateExist); err != nil {
				return false, fmt.Errorf("failed to update on delete src_cidr_map: %w", err)
			}
			log.Debug().Msgf("Updated referenced entry %v", k.String())
		}

	}

	if found {
		return false, nil
	}

	if err = d.srcMap.Delete(lpmKey); err != nil {
		return false, fmt.Errorf("failed to delete src_cidr_map: %w", err)
	}
	log.Debug().Msgf("Deleted srcMap %v", lpmKey.String())
	return true, nil
}

func (fm *FirewallManager) ListRules() (out []*proto.RuleOut, err error) {
	fm.rulesMtx.Lock()
	defer fm.rulesMtx.Unlock()
	rulesList := make(map[RuleIdentifier]*proto.RuleOut)
	for id, rule := range fm.ruleDB {
		var packets uint64
		var bytes uint64
		allStats := make([]bpf.FwPktStats, runtime.NumCPU())
		if err = fm.bpfObjs.Stats.Lookup(&id, allStats[:]); err == nil {
			for _, stats := range allStats {
				packets += stats.Pkts
				bytes += stats.Bytes
			}
		}

		srcCIDR, dstCIDR, ipProtocol, srcPort, dstPort := getRuleFields(rule)

		ruleId := RuleIdentifier{
			SrcCIDR:  cidrToString(srcCIDR),
			DstCIDR:  cidrToString(dstCIDR),
			Protocol: protocolToString(ipProtocol),
			SrcPort:  srcPort,
			DstPort:  dstPort,
		}

		if _, exists := rulesList[ruleId]; !exists {
			rulesList[ruleId] = &proto.RuleOut{
				Rule:    rule,
				Packets: packets,
				Bytes:   bytes,
			}
		} else {
			rulesList[ruleId].Packets += packets
			rulesList[ruleId].Bytes += bytes
		}

	}
	for _, rule := range rulesList {
		out = append(out, rule)
	}
	return
}
