// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/dsa/8021q.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>

#include "ralink_fe.h"
#include "ra_ppe.h"
#include "ra_ppe_offload.h"
#include "ra_ppe_v2_foe.h"
#include "ra_ppe_v2_regs.h"

/*
 * PPEv2-private flow state.
 *
 * struct ra_flow_entry must remain first: the generic offload layer
 * owns rhashtable and RCU lifetime through that pointer.
 */
struct ra_ppe_v2_flow_entry {
	struct ra_flow_entry flow;

	/*
	 * Immutable PPEv2 BIND template after publication to the software
	 * flow tables. RX copies it and supplies the exact tuple learned by
	 * hardware before committing the FOE entry.
	 */
	struct ra_ppe_v2_foe_entry bind;
};

/*
 * Resolved PPEv2 egress state.
 *
 * PPEv2 describes the resulting VLAN stack rather than PPEv1-style
 * INSERT/DELETE/MODIFY operations.
 */
struct ra_ppe_v2_output {
	u16 vlan1;
	u16 vlan2;
	u8 vlan_layers;

	bool pppoe;
	u16 pppoe_id;

	/*
	 * Force-port index carried by PPEv2 information block 2.
	 */
	u8 fpidx;
};

static inline struct ra_ppe_v2_flow_entry *
ra_ppe_v2_flow_entry(struct ra_flow_entry *flow)
{
	return container_of(flow, struct ra_ppe_v2_flow_entry, flow);
}

static inline struct ra_ppe_v2_foe_entry *
ra_ppe_v2_foe_entry(struct ra_ppe *ppe, u32 index)
{
	return (struct ra_ppe_v2_foe_entry *)ppe->foe_table + index;
}

static u16 ra_ppe_v2_vlan_tci(u16 vid, u8 prio)
{
	return (vid & VLAN_VID_MASK) |
	       ((prio << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK);
}

static void
ra_ppe_v2_ipv6_to_foe(u32 dst[4], const struct in6_addr *src)
{
	int i;

	for (i = 0; i < 4; i++)
		dst[i] = get_unaligned_be32(&src->s6_addr[i * sizeof(u32)]);
}

static void
ra_ppe_v2_ipv6_from_foe(struct in6_addr *dst, const u32 src[4])
{
	int i;

	for (i = 0; i < 4; i++)
		put_unaligned_be32(src[i],
				  &dst->s6_addr[i * sizeof(u32)]);
}

static bool
ra_ppe_v2_flow_key_from_foe(struct ra_flow_key *key,
			    const struct ra_ppe_v2_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	memset(key, 0, sizeof(*key));

	key->ip_proto = (ib1 & RA_PPE_V2_IB1_UDP) ?
			IPPROTO_UDP : IPPROTO_TCP;

	switch (FIELD_GET(RA_PPE_V2_IB1_PKT_TYPE, ib1)) {
	case RA_PPE_V2_FOE_IPV4_HNAPT:
		key->n_proto = htons(ETH_P_IP);

		key->src_port = htons(foe->ipv4.sport);
		key->dst_port = htons(foe->ipv4.dport);

		key->src.ipv4 = htonl(foe->ipv4.sip);
		key->dst.ipv4 = htonl(foe->ipv4.dip);

		return true;

	case RA_PPE_V2_FOE_IPV6_5T_ROUTE:
		key->n_proto = htons(ETH_P_IPV6);

		key->src_port = htons(foe->ipv6_5t.sport);
		key->dst_port = htons(foe->ipv6_5t.dport);

		ra_ppe_v2_ipv6_from_foe(&key->src.ipv6,
					foe->ipv6_5t.sip);
		ra_ppe_v2_ipv6_from_foe(&key->dst.ipv6,
					foe->ipv6_5t.dip);

		return true;

	default:
		return false;
	}
}

static bool
ra_ppe_v2_flow_foe_matches(const struct ra_ppe_v2_foe_entry *foe,
			   const struct ra_flow_key *key)
{
	struct ra_flow_key foe_key;

	if (!ra_ppe_v2_flow_key_from_foe(&foe_key, foe))
		return false;

	return !memcmp(&foe_key, key, sizeof(foe_key));
}

static bool
ra_ppe_v2_flow_foe_is_bound(const struct ra_ppe_v2_foe_entry *foe,
			    const struct ra_flow_key *key)
{
	if (ra_ppe_v2_foe_state(foe) != RA_PPE_V2_FOE_STATE_BIND)
		return false;

	/*
	 * The FOE table is coherent DMA memory. Coherency does not imply
	 * ordering: after observing BIND, order subsequent descriptor reads
	 * behind that state observation.
	 */
	dma_rmb();

	return ra_ppe_v2_flow_foe_matches(foe, key);
}

static void
ra_ppe_v2_foe_commit_locked(struct ra_ppe *ppe, u32 index,
			    const struct ra_ppe_v2_foe_entry *entry)
{
	struct ra_ppe_v2_foe_entry bind;
	struct ra_ppe_v2_foe_entry *dst;
	u32 ib1, final_ib1;
	u16 timestamp;

	lockdep_assert_held(&ppe->lock);

	if (WARN_ON_ONCE(index >= ppe->foe_entries))
		return;

	bind = *entry;

	timestamp = ra_ppe_r32(ppe, RA_V2_REG_FOE_TS) &
		    FIELD_MAX(RA_PPE_V2_IB1_BIND_TIMESTAMP);

	ib1 = bind.info_blk1;
	ib1 &= ~(RA_PPE_V2_IB1_BIND_TIMESTAMP |
		 RA_PPE_V2_IB1_TTL |
		 RA_PPE_V2_IB1_STATE);

	ib1 |= FIELD_PREP(RA_PPE_V2_IB1_BIND_TIMESTAMP, timestamp);
	ib1 |= RA_PPE_V2_IB1_TTL;
	ib1 |= FIELD_PREP(RA_PPE_V2_IB1_STATE,
			  RA_PPE_V2_FOE_STATE_BIND);

	final_ib1 = ib1;

	/*
	 * Copy the complete descriptor as INVALID, then publish BIND only
	 * after the remaining descriptor words are visible to PPE.
	 */
	bind.info_blk1 =
		(final_ib1 & ~RA_PPE_V2_IB1_STATE) |
		FIELD_PREP(RA_PPE_V2_IB1_STATE,
			   RA_PPE_V2_FOE_STATE_INVALID);

	dst = ra_ppe_v2_foe_entry(ppe, index);

	memcpy(dst, &bind, sizeof(*dst));

	dma_wmb();

	WRITE_ONCE(dst->info_blk1, final_ib1);
}

static void
ra_ppe_v2_foe_clear_locked(struct ra_ppe *ppe, u32 index)
{
	struct ra_ppe_v2_foe_entry *foe;
	u32 ib1;

	lockdep_assert_held(&ppe->lock);

	if (WARN_ON_ONCE(index >= ppe->foe_entries))
		return;

	foe = ra_ppe_v2_foe_entry(ppe, index);

	ib1 = READ_ONCE(foe->info_blk1);
	ib1 &= ~RA_PPE_V2_IB1_STATE;
	ib1 |= FIELD_PREP(RA_PPE_V2_IB1_STATE,
			  RA_PPE_V2_FOE_STATE_INVALID);

	WRITE_ONCE(foe->info_blk1, ib1);

	/*
	 * Ensure the invalidation is visible before software reuses or
	 * forgets this hardware association.
	 */
	dma_wmb();
}

static int
ra_ppe_v2_resolve_output(struct ra_ppe *ppe,
			 struct flow_cls_offload *f,
			 const struct ra_flow_data *data,
			 struct ra_ppe_v2_output *out)
{
	struct dsa_port *dp;
	struct net_device *br;

	if (data->vlan.push &&
	    data->vlan.push_proto != htons(ETH_P_8021Q)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv2 supports 802.1Q VLAN push only");
		return -EOPNOTSUPP;
	}

	dp = dsa_port_from_netdev(data->out_dev);
	if (IS_ERR(dp)) {
		if (data->out_dev != ppe->fe->ndev)
			return -EOPNOTSUPP;

		out->fpidx = RA_PPE_V2_FPIDX_LOOKUP;

		if (data->vlan.push) {
			out->vlan1 = ra_ppe_v2_vlan_tci(
					data->vlan.push_vid,
					data->vlan.push_prio);
			out->vlan_layers = 1;
		}

		goto pppoe;
	}

	if (!dp->cpu_dp || !dp->cpu_dp->tag_ops ||
	    dp->cpu_dp->tag_ops->proto != DSA_TAG_PROTO_RALINK)
		return -EOPNOTSUPP;

	if (dp->index > 5)
		return -EOPNOTSUPP;

	out->fpidx = dp->index;

	br = dsa_port_bridge_dev_get(dp);

	if (br && br_vlan_enabled(br)) {
		u16 pvid;
		int err;

		if (data->vlan.push) {
			out->vlan1 = ra_ppe_v2_vlan_tci(
					data->vlan.push_vid,
					data->vlan.push_prio);
			out->vlan_layers = 1;
			goto pppoe;
		}

		if (data->vlan.pop)
			goto pppoe;

		rcu_read_lock();
		err = br_vlan_get_pvid_rcu(br, &pvid);
		rcu_read_unlock();
		if (err)
			return err;

		out->vlan1 = pvid;
		out->vlan_layers = 1;
		goto pppoe;
	}

	if (br) {
		unsigned int bridge_num;

		bridge_num = dsa_port_bridge_num_get(dp);

		out->vlan1 = dsa_tag_8021q_bridge_vid(bridge_num);
		out->vlan_layers = 1;

		goto pppoe;
	}

	out->vlan1 = dsa_tag_8021q_standalone_vid(dp);
	out->vlan_layers = 1;

pppoe:
	if (data->pppoe.push) {
		out->pppoe = true;
		out->pppoe_id = data->pppoe.sid;
	}

	return 0;
}

static u32
ra_ppe_v2_build_ib1(const struct ra_flow_data *data,
		    const struct ra_ppe_v2_output *out,
		    enum ra_ppe_v2_foe_type type)
{
	u32 ib1;

	ib1 = FIELD_PREP(RA_PPE_V2_IB1_PKT_TYPE, type);

	if (data->l4proto == IPPROTO_UDP)
		ib1 |= RA_PPE_V2_IB1_UDP;

	ib1 |= FIELD_PREP(RA_PPE_V2_IB1_VLAN_LAYER,
			  out->vlan_layers);

	if (out->pppoe)
		ib1 |= RA_PPE_V2_IB1_PPPOE;

	ib1 |= RA_PPE_V2_IB1_TTL;
	ib1 |= RA_PPE_V2_IB1_KEEPALIVE;

	/*
	 * STATIC, cache and tunnel-removal policy remain disabled.
	 * Timestamp and final state are supplied when the entry is bound.
	 */
	ib1 |= FIELD_PREP(RA_PPE_V2_IB1_STATE,
			  RA_PPE_V2_FOE_STATE_INVALID);

	return ib1;
}

static u32
ra_ppe_v2_build_ib2(const struct ra_ppe_v2_output *out)
{
	/*
	 * Only the force-port index is required for the basic routed
	 * offload path. QoS, metering and accounting remain disabled.
	 */
	return FIELD_PREP(RA_PPE_V2_IB2_FPIDX, out->fpidx);
}

static void
ra_ppe_v2_build_ipv4(struct ra_ppe_v2_foe_entry *foe,
		     const struct ra_flow_data *data,
		     const struct ra_ppe_v2_output *out)
{
	struct ra_ppe_v2_foe_ipv4 *ipv4 = &foe->ipv4;

	ipv4->info_blk1 =
		ra_ppe_v2_build_ib1(data, out,
				    RA_PPE_V2_FOE_IPV4_HNAPT);

	ipv4->sip = ntohl(data->src_addr.ipv4);
	ipv4->dip = ntohl(data->dst_addr.ipv4);
	ipv4->sport = ntohs(data->src_port);
	ipv4->dport = ntohs(data->dst_port);

	ipv4->new_sip = ntohl(data->new_src_addr.ipv4);
	ipv4->new_dip = ntohl(data->new_dst_addr.ipv4);
	ipv4->new_sport = ntohs(data->new_src_port);
	ipv4->new_dport = ntohs(data->new_dst_port);

	ipv4->info_blk2 = ra_ppe_v2_build_ib2(out);

	if (out->vlan_layers) {
		ipv4->vlan1 = out->vlan1;
		ipv4->etype = ETH_P_8021Q;
	}

	if (out->vlan_layers > 1)
		ipv4->vlan2 = out->vlan2;

	ra_ppe_v2_foe_set_mac(ipv4->dmac_hi, ipv4->dmac_lo,
			      data->eth.h_dest);
	ra_ppe_v2_foe_set_mac(ipv4->smac_hi, ipv4->smac_lo,
			      data->eth.h_source);

	if (out->pppoe)
		ipv4->pppoe_id = out->pppoe_id;
}

static void
ra_ppe_v2_build_ipv6_5t(struct ra_ppe_v2_foe_entry *foe,
			const struct ra_flow_data *data,
			const struct ra_ppe_v2_output *out)
{
	struct ra_ppe_v2_foe_ipv6_5t *ipv6 = &foe->ipv6_5t;

	ipv6->info_blk1 =
		ra_ppe_v2_build_ib1(data, out,
				    RA_PPE_V2_FOE_IPV6_5T_ROUTE);

	ra_ppe_v2_ipv6_to_foe(ipv6->sip, &data->src_addr.ipv6);
	ra_ppe_v2_ipv6_to_foe(ipv6->dip, &data->dst_addr.ipv6);

	ipv6->sport = ntohs(data->src_port);
	ipv6->dport = ntohs(data->dst_port);

	ipv6->info_blk2 = ra_ppe_v2_build_ib2(out);

	if (out->vlan_layers) {
		ipv6->vlan1 = out->vlan1;
		ipv6->etype = ETH_P_8021Q;
	}

	if (out->vlan_layers > 1)
		ipv6->vlan2 = out->vlan2;

	ra_ppe_v2_foe_set_mac(ipv6->dmac_hi, ipv6->dmac_lo,
			      data->eth.h_dest);
	ra_ppe_v2_foe_set_mac(ipv6->smac_hi, ipv6->smac_lo,
			      data->eth.h_source);

	if (out->pppoe)
		ipv6->pppoe_id = out->pppoe_id;
}

static int
ra_ppe_v2_flow_prepare(struct ra_ppe *ppe,
		       struct flow_cls_offload *f,
		       const struct ra_flow_data *data,
		       struct ra_flow_entry **flow)
{
	struct ra_ppe_v2_flow_entry *entry;
	struct ra_ppe_v2_output output = {};
	int err;

	switch (data->n_proto) {
	case htons(ETH_P_IP):
		break;

	case htons(ETH_P_IPV6):
		/*
		 * The PPEv2 IPv6 5T format is a routing entry, not an IPv6
		 * NAT entry. Reject any L3/L4 tuple translation.
		 *
		 * The generic parser already rejects IPv6 address mangles;
		 * keep this check here as generation-specific validation.
		 */
		if (memcmp(&data->src_addr.ipv6,
			   &data->new_src_addr.ipv6,
			   sizeof(data->src_addr.ipv6)) ||
		    memcmp(&data->dst_addr.ipv6,
			   &data->new_dst_addr.ipv6,
			   sizeof(data->dst_addr.ipv6)) ||
		    data->src_port != data->new_src_port ||
		    data->dst_port != data->new_dst_port) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "PPEv2 IPv6 5-tuple routing does not support NAT");
			return -EOPNOTSUPP;
		}
		break;

	default:
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported network protocol for PPEv2");
		return -EOPNOTSUPP;
	}

	err = ra_ppe_v2_resolve_output(ppe, f, data, &output);
	if (err)
		return err;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memset(&entry->bind, 0, sizeof(entry->bind));

	if (data->n_proto == htons(ETH_P_IP))
		ra_ppe_v2_build_ipv4(&entry->bind, data, &output);
	else
		ra_ppe_v2_build_ipv6_5t(&entry->bind, data, &output);

	*flow = &entry->flow;

	return 0;
}

static void
ra_ppe_v2_flow_remove(struct ra_ppe *ppe,
		      struct ra_flow_entry *entry)
{
	unsigned long flags;

	lockdep_assert_held(&ppe->flow_lock);

	spin_lock_irqsave(&ppe->lock, flags);

	if (entry->hash_valid) {
		u16 hash = entry->hash;

		/*
		 * Hardware may already have aged or reused the remembered
		 * slot. Clear it only while it remains the BIND belonging to
		 * this software flow.
		 */
		if (hash < ppe->foe_entries &&
		    ra_ppe_v2_flow_foe_is_bound(
			    ra_ppe_v2_foe_entry(ppe, hash),
			    &entry->key))
			ra_ppe_v2_foe_clear_locked(ppe, hash);

		entry->hash_valid = false;
	}

	spin_unlock_irqrestore(&ppe->lock, flags);
}

static void
ra_ppe_v2_preserve_learned_tuple(struct ra_ppe_v2_foe_entry *bind,
				 const struct ra_ppe_v2_foe_entry *hw)
{
	switch (ra_ppe_v2_foe_type(hw)) {
	case RA_PPE_V2_FOE_IPV4_HNAPT:
		bind->ipv4.sip = hw->ipv4.sip;
		bind->ipv4.dip = hw->ipv4.dip;
		bind->ipv4.sport = hw->ipv4.sport;
		bind->ipv4.dport = hw->ipv4.dport;
		break;

	case RA_PPE_V2_FOE_IPV6_5T_ROUTE:
		memcpy(bind->ipv6_5t.sip, hw->ipv6_5t.sip,
		       sizeof(bind->ipv6_5t.sip));
		memcpy(bind->ipv6_5t.dip, hw->ipv6_5t.dip,
		       sizeof(bind->ipv6_5t.dip));

		bind->ipv6_5t.sport = hw->ipv6_5t.sport;
		bind->ipv6_5t.dport = hw->ipv6_5t.dport;
		break;

	default:
		break;
	}
}

static bool
ra_ppe_v2_offload_check(struct ra_ppe *ppe, u16 foe, bool keepalive)
{
	struct ra_ppe_v2_flow_entry *v2_entry;
	struct ra_ppe_v2_foe_entry *hw_entry;
	struct ra_ppe_v2_foe_entry bind;
	struct ra_flow_entry *entry;
	struct ra_flow_key key;
	unsigned long flags;
	bool ret = false;

	if (!ppe || foe >= ppe->foe_entries)
		return false;

	rcu_read_lock();

	spin_lock_irqsave(&ppe->lock, flags);

	hw_entry = ra_ppe_v2_foe_entry(ppe, foe);

	if (keepalive) {
		if (ra_ppe_v2_foe_state(hw_entry) !=
		    RA_PPE_V2_FOE_STATE_BIND)
			goto out_unlock;
	} else {
		if (!ra_ppe_v2_foe_is_unbind(hw_entry))
			goto out_unlock;
	}

	dma_rmb();

	if (!ra_ppe_v2_flow_key_from_foe(&key, hw_entry))
		goto out_unlock;

	entry = ra_ppe_flow_lookup_tuple(ppe, &key);
	if (!entry || entry->dead)
		goto out_unlock;

	if (keepalive) {
		if (!entry->hash_valid || entry->hash != foe)
			goto out_unlock;

		WRITE_ONCE(entry->lastused, jiffies);
		ret = true;
		goto out_unlock;
	}

	/*
	 * Retain a previous hardware association while its old slot remains
	 * a matching BIND. Otherwise it has aged out or been reused.
	 */
	if (entry->hash_valid && entry->hash != foe) {
		if (entry->hash < ppe->foe_entries &&
		    ra_ppe_v2_flow_foe_is_bound(
			    ra_ppe_v2_foe_entry(ppe, entry->hash),
			    &entry->key))
			goto out_unlock;

		entry->hash_valid = false;
	}

	v2_entry = ra_ppe_v2_flow_entry(entry);
	bind = v2_entry->bind;

	/*
	 * Preserve the exact original tuple learned by PPEv2 before
	 * replacing the UNBIND descriptor with the Linux-authorized BIND
	 * template.
	 */
	ra_ppe_v2_preserve_learned_tuple(&bind, hw_entry);

	ra_ppe_v2_foe_commit_locked(ppe, foe, &bind);

	entry->hash = foe;
	entry->hash_valid = true;
	WRITE_ONCE(entry->lastused, jiffies);

	ret = true;

out_unlock:
	spin_unlock_irqrestore(&ppe->lock, flags);
	rcu_read_unlock();

	return ret;
}

const struct ra_ppe_offload_ops ra_ppe_v2_offload_ops = {
	.prepare	= ra_ppe_v2_flow_prepare,
	.remove		= ra_ppe_v2_flow_remove,
	.check		= ra_ppe_v2_offload_check,
};
