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

#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>

#include "ralink_fe.h"
#include "ra_ppe.h"
#include "ra_ppe_offload.h"
#include "ra_ppe_v1_foe.h"
#include "ra_ppe_v1_regs.h"

/*
 * PPEv1-private flow state.
 *
 * struct ra_flow_entry must remain first: the generic offload layer
 * owns rhashtable and RCU lifetime through that pointer.
 */
struct ra_ppe_v1_flow_entry {
	struct ra_flow_entry flow;

	/*
	 * Immutable PPEv1 BIND template after publication to the software
	 * flow tables. RX copies it and supplies the exact tuple learned by
	 * hardware before committing the FOE entry.
	 */
	struct ra_ppe_v1_foe_entry bind;
};

struct ra_ppe_v1_output {
	u16 vlan1;
	u16 vlan2;

	enum ra_ppe_v1_action vlan1_action;
	enum ra_ppe_v1_action vlan2_action;

	bool pppoe;
	u16 pppoe_id;

	u8 dp;
};

static inline struct ra_ppe_v1_flow_entry *
ra_ppe_v1_flow_entry(struct ra_flow_entry *flow)
{
	return container_of(flow, struct ra_ppe_v1_flow_entry, flow);
}

static inline struct ra_ppe_v1_foe_entry *
ra_ppe_v1_foe_entry(struct ra_ppe *ppe, u32 index)
{
	return (struct ra_ppe_v1_foe_entry *)ppe->foe_table + index;
}

static void
ra_ppe_v1_flow_key_from_foe(struct ra_flow_key *key,
			    const struct ra_ppe_v1_foe_entry *foe)
{
	const struct ra_ppe_v1_foe_ipv4 *ipv4 = &foe->ipv4;
	u32 ib1 = READ_ONCE(foe->info_blk1);

	memset(key, 0, sizeof(*key));

	key->n_proto = htons(ETH_P_IP);
	key->ip_proto = (ib1 & RA_PPE_V1_IB1_UDP) ?
			IPPROTO_UDP : IPPROTO_TCP;

	key->src_port = htons(ipv4->sport);
	key->dst_port = htons(ipv4->dport);

	key->src.ipv4 = htonl(ipv4->sip);
	key->dst.ipv4 = htonl(ipv4->dip);
}

static bool
ra_ppe_v1_flow_foe_matches(const struct ra_ppe_v1_foe_entry *foe,
			   const struct ra_flow_key *key)
{
	struct ra_flow_key foe_key;

	ra_ppe_v1_flow_key_from_foe(&foe_key, foe);

	return !memcmp(&foe_key, key, sizeof(foe_key));
}

static bool
ra_ppe_v1_flow_foe_is_bound(const struct ra_ppe_v1_foe_entry *foe,
			    const struct ra_flow_key *key)
{
	if (ra_ppe_v1_foe_state(foe) != RA_PPE_V1_FOE_STATE_BIND)
		return false;

	/*
	 * The FOE table is coherent DMA memory. Coherency does not imply
	 * ordering: after observing BIND, order subsequent descriptor reads
	 * behind that state observation.
	 */
	dma_rmb();

	if (!ra_ppe_v1_foe_is_ipv4_hnapt(foe))
		return false;

	return ra_ppe_v1_flow_foe_matches(foe, key);
}

static void
ra_ppe_v1_foe_commit_locked(struct ra_ppe *ppe, u32 index,
			    const struct ra_ppe_v1_foe_entry *entry)
{
	struct ra_ppe_v1_foe_entry bind;
	struct ra_ppe_v1_foe_entry *dst;
	u32 ib1, final_ib1;
	u16 timestamp;

	lockdep_assert_held(&ppe->lock);

	if (WARN_ON_ONCE(index >= ppe->foe_entries))
		return;

	bind = *entry;

	timestamp = ra_ppe_r32(ppe, RA_REG_FOE_TS) & 0xffff;

	/*
	 * Install the current hardware timestamp and construct the final
	 * BIND state word.
	 */
	ib1 = bind.info_blk1;
	ib1 &= ~(RA_PPE_V1_IB1_BIND_TIMESTAMP |
		 RA_PPE_V1_IB1_TTL |
		 RA_PPE_V1_IB1_STATE);

	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_BIND_TIMESTAMP, timestamp);
	ib1 |= RA_PPE_V1_IB1_TTL;
	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_STATE,
			  RA_PPE_V1_FOE_STATE_BIND);

	final_ib1 = ib1;

	/*
	 * Copy the complete descriptor while its state remains INVALID.
	 * Publish BIND only after all remaining words are globally visible.
	 */
	bind.info_blk1 =
		(final_ib1 & ~RA_PPE_V1_IB1_STATE) |
		FIELD_PREP(RA_PPE_V1_IB1_STATE,
			   RA_PPE_V1_FOE_STATE_INVALID);

	dst = ra_ppe_v1_foe_entry(ppe, index);

	memcpy(dst, &bind, sizeof(*dst));

	dma_wmb();

	WRITE_ONCE(dst->info_blk1, final_ib1);
}

static void
ra_ppe_v1_foe_clear_locked(struct ra_ppe *ppe, u32 index)
{
	struct ra_ppe_v1_foe_entry *foe;

	lockdep_assert_held(&ppe->lock);

	if (WARN_ON_ONCE(index >= ppe->foe_entries))
		return;

	foe = ra_ppe_v1_foe_entry(ppe, index);

	/*
	 * All-zero is PPEv1's INVALID entry representation.
	 */
	memset(foe, 0, sizeof(*foe));
}

static int
ra_ppe_v1_resolve_output(struct ra_ppe *ppe,
			 struct flow_cls_offload *f,
			 const struct ra_flow_data *data,
			 struct ra_ppe_v1_output *out)
{
	struct dsa_port *dp;
	struct net_device *br;

	/*
	 * PPEv1 supports only 802.1Q VLAN insertion in this path.
	 */
	if (data->vlan.push &&
	    data->vlan.push_proto != htons(ETH_P_8021Q)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 supports 802.1Q VLAN push only");
		return -EOPNOTSUPP;
	}

	dp = dsa_port_from_netdev(data->out_dev);
	if (IS_ERR(dp)) {
		if (data->out_dev != ppe->fe->ndev)
			return -EOPNOTSUPP;

		out->dp = 1;

		/*
		 * Non-DSA output. Translate logical flower VLAN operations
		 * directly into PPEv1 smart-VLAN semantics.
		 */
		if (data->vlan.pop && data->vlan.push) {
			out->vlan1 = data->vlan.push_vid;
			out->vlan1_action = RA_PPE_V1_ACT_MODIFY;
		} else if (data->vlan.push) {
			out->vlan1 = data->vlan.push_vid;
			out->vlan1_action = RA_PPE_V1_ACT_INSERT;
		} else if (data->vlan.pop) {
			out->vlan1_action = RA_PPE_V1_ACT_DELETE;
		} else {
			out->vlan1_action = RA_PPE_V1_ACT_NONE;
		}

		goto pppoe;
	}

	if (!dp->cpu_dp || !dp->cpu_dp->tag_ops ||
	    dp->cpu_dp->tag_ops->proto != DSA_TAG_PROTO_RALINK)
		return -EOPNOTSUPP;

	br = dsa_port_bridge_dev_get(dp);

	if (br && br_vlan_enabled(br)) {
		u16 pvid;
		int err;

		out->dp = 1;

		if (data->vlan.push) {
			out->vlan1 = data->vlan.push_vid;
			out->vlan1_action = data->vlan.pop ?
					    RA_PPE_V1_ACT_MODIFY :
					    RA_PPE_V1_ACT_INSERT;

			out->vlan2_action = RA_PPE_V1_ACT_DELETE;
			goto pppoe;
		}

		rcu_read_lock();
		err = br_vlan_get_pvid_rcu(br, &pvid);
		rcu_read_unlock();
		if (err)
			return err;

		out->vlan1 = pvid;
		out->vlan1_action = data->vlan.pop ?
				    RA_PPE_V1_ACT_DELETE :
				    RA_PPE_V1_ACT_INSERT;

		goto pppoe;
	}

	if (br) {
		unsigned int bridge_num;

		bridge_num = dsa_port_bridge_num_get(dp);

		out->vlan1 = dsa_tag_8021q_bridge_vid(bridge_num);
		out->vlan1_action = RA_PPE_V1_ACT_INSERT;
		out->dp = 1;

		goto pppoe;
	}

	out->vlan1 = dsa_tag_8021q_standalone_vid(dp);
	out->vlan1_action = RA_PPE_V1_ACT_INSERT;
	out->dp = 2;

pppoe:
	/*
	 * Keep PPPoE translation PPEv1-local. The generic flow only
	 * describes the logical PPPOE_PUSH action requested by Linux.
	 */
	if (data->pppoe.push) {
		out->pppoe = true;
		out->pppoe_id = data->pppoe.sid;
	}

	return 0;
}

static void
ra_ppe_v1_build_foe(struct ra_ppe_v1_foe_entry *foe,
		    const struct ra_flow_data *data,
		    const struct ra_ppe_v1_output *out)
{
	struct ra_ppe_v1_foe_ipv4 *ipv4 = &foe->ipv4;
	u32 ib1, ib2;

	memset(foe, 0, sizeof(*foe));

	/*
	 * PPEv1 currently accelerates IPv4 HNAPT only. Keep the descriptor
	 * construction explicit instead of relying on compiler bitfield
	 * layout.
	 */
	ib1 = FIELD_PREP(RA_PPE_V1_IB1_PKT_TYPE,
			 RA_PPE_V1_FOE_IPV4_HNAPT);

	if (data->l4proto == IPPROTO_UDP)
		ib1 |= RA_PPE_V1_IB1_UDP;

	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_VLAN1_ACTION,
			  out->vlan1_action);
	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_VLAN2_ACTION,
			  out->vlan2_action);
	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_SNAP_ACTION,
			  RA_PPE_V1_ACT_NONE);

	/*
	 * flow_action provides PPPOE_PUSH but no corresponding PPPOE_POP.
	 * PPEv1 DELETE is harmless for an unencapsulated routed packet, so
	 * retain the existing PPEv1 policy here.
	 */
	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_PPPOE_ACTION,
			  out->pppoe ?
			  RA_PPE_V1_ACT_INSERT :
			  RA_PPE_V1_ACT_DELETE);

	ib1 |= RA_PPE_V1_IB1_TTL;
	ib1 |= RA_PPE_V1_IB1_KEEPALIVE;

	/*
	 * STATIC remains clear. State and timestamp are finalized by
	 * ra_ppe_v1_foe_commit_locked().
	 *
	 * INVALID is zero, but encode it explicitly to document the
	 * publication protocol.
	 */
	ib1 |= FIELD_PREP(RA_PPE_V1_IB1_STATE,
			  RA_PPE_V1_FOE_STATE_INVALID);

	ipv4->info_blk1 = ib1;

	/*
	 * PPEv1 IPv4 HNAPT tuple fields are stored in CPU order. Keep the
	 * generic flow representation in network order and convert only at
	 * the hardware descriptor boundary.
	 */
	ipv4->sip = ntohl(data->src_addr.ipv4);
	ipv4->dip = ntohl(data->dst_addr.ipv4);
	ipv4->sport = ntohs(data->src_port);
	ipv4->dport = ntohs(data->dst_port);

	ipv4->new_sip = ntohl(data->new_src_addr.ipv4);
	ipv4->new_dip = ntohl(data->new_dst_addr.ipv4);
	ipv4->new_sport = ntohs(data->new_src_port);
	ipv4->new_dport = ntohs(data->new_dst_port);

	ra_ppe_v1_foe_set_mac(ipv4->dmac_hi, data->eth.h_dest);
	ra_ppe_v1_foe_set_mac(ipv4->smac_hi, data->eth.h_source);

	if (out->vlan1_action == RA_PPE_V1_ACT_INSERT ||
	    out->vlan1_action == RA_PPE_V1_ACT_MODIFY)
		ipv4->vlan1 = out->vlan1;

	if (out->vlan2_action == RA_PPE_V1_ACT_INSERT ||
	    out->vlan2_action == RA_PPE_V1_ACT_MODIFY)
		ipv4->vlan2 = out->vlan2;

	if (out->pppoe)
		ipv4->pppoe_id = out->pppoe_id;

	/*
	 * Force the packet to the PPEv1 destination selected by output
	 * topology. All other IB2 policy fields retain their zero defaults.
	 */
	ib2 = RA_PPE_V1_IB2_FD |
	      FIELD_PREP(RA_PPE_V1_IB2_DP, out->dp);

	ipv4->info_blk2 = ib2;
}

static int
ra_ppe_v1_flow_prepare(struct ra_ppe *ppe,
		       struct flow_cls_offload *f,
		       const struct ra_flow_data *data,
		       struct ra_flow_entry **flow)
{
	struct ra_ppe_v1_flow_entry *entry;
	struct ra_ppe_v1_output output = {};
	int err;

	/*
	 * The generic parser can represent IPv6 for PPEv2, but PPEv1
	 * remains strictly IPv4 HNAPT.
	 */
	if (data->n_proto != htons(ETH_P_IP)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 supports IPv4 flows only");
		return -EOPNOTSUPP;
	}

	err = ra_ppe_v1_resolve_output(ppe, f, data, &output);
	if (err)
		return err;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	ra_ppe_v1_build_foe(&entry->bind, data, &output);

	*flow = &entry->flow;

	return 0;
}

static void
ra_ppe_v1_flow_remove(struct ra_ppe *ppe,
		      struct ra_flow_entry *entry)
{
	unsigned long flags;

	lockdep_assert_held(&ppe->flow_lock);

	spin_lock_irqsave(&ppe->lock, flags);

	if (entry->hash_valid) {
		u16 hash = entry->hash;

		/*
		 * Hardware may already have aged or reused the remembered
		 * slot. Clear it only when it is still the BIND belonging to
		 * this software flow.
		 */
		if (hash < ppe->foe_entries &&
		    ra_ppe_v1_flow_foe_is_bound(
			    ra_ppe_v1_foe_entry(ppe, hash),
			    &entry->key))
			ra_ppe_v1_foe_clear_locked(ppe, hash);

		entry->hash_valid = false;
	}

	spin_unlock_irqrestore(&ppe->lock, flags);
}

static bool
ra_ppe_v1_offload_check(struct ra_ppe *ppe, u16 foe, bool keepalive)
{
	struct ra_ppe_v1_flow_entry *v1_entry;
	struct ra_ppe_v1_foe_entry *hw_entry;
	struct ra_ppe_v1_foe_entry bind;
	struct ra_flow_entry *entry;
	struct ra_flow_key key;
	unsigned long flags;
	bool ret = false;

	if (!ppe || foe >= ppe->foe_entries)
		return false;

	/*
	 * The tuple table is read from RX/NAPI while the TC control path may
	 * remove entries. RCU protects ra_flow_entry lifetime; ppe->lock
	 * protects hardware association state and direct FOE access.
	 */
	rcu_read_lock();

	spin_lock_irqsave(&ppe->lock, flags);

	hw_entry = ra_ppe_v1_foe_entry(ppe, foe);

	if (keepalive) {
		/*
		 * A keepalive reason must originate from a BIND entry.
		 */
		if (ra_ppe_v1_foe_state(hw_entry) !=
		    RA_PPE_V1_FOE_STATE_BIND)
			goto out_unlock;
	} else {
		/*
		 * Promotion is valid only for a hardware-learned UNBIND
		 * entry.
		 */
		if (!ra_ppe_v1_foe_is_unbind(hw_entry))
			goto out_unlock;
	}

	/*
	 * The FOE table is coherent DMA memory. After observing the
	 * hardware-published state, order subsequent descriptor reads
	 * behind that observation.
	 */
	dma_rmb();

	if (!ra_ppe_v1_foe_is_ipv4_hnapt(hw_entry))
		goto out_unlock;

	ra_ppe_v1_flow_key_from_foe(&key, hw_entry);

	entry = ra_ppe_flow_lookup_tuple(ppe, &key);
	if (!entry || entry->dead)
		goto out_unlock;

	if (keepalive) {
		/*
		 * Accept activity only from the FOE slot currently associated
		 * with this software flow. This prevents a recycled hardware
		 * slot from refreshing an unrelated flow.
		 */
		if (!entry->hash_valid || entry->hash != foe)
			goto out_unlock;

		WRITE_ONCE(entry->lastused, jiffies);
		ret = true;

		goto out_unlock;
	}

	/*
	 * If software remembers a different FOE slot, treat that association
	 * as active only while the old slot remains a matching BIND.
	 *
	 * Otherwise the old hardware association has aged out or the slot
	 * has been reused and may be forgotten.
	 */
	if (entry->hash_valid && entry->hash != foe) {
		if (entry->hash < ppe->foe_entries &&
		    ra_ppe_v1_flow_foe_is_bound(
			    ra_ppe_v1_foe_entry(ppe, entry->hash),
			    &entry->key))
			goto out_unlock;

		entry->hash_valid = false;
	}

	v1_entry = ra_ppe_v1_flow_entry(entry);
	bind = v1_entry->bind;

	/*
	 * Preserve the exact original tuple learned by PPEv1. These values
	 * are already in the hardware's CPU-order FOE representation.
	 */
	bind.ipv4.sip = hw_entry->ipv4.sip;
	bind.ipv4.dip = hw_entry->ipv4.dip;
	bind.ipv4.sport = hw_entry->ipv4.sport;
	bind.ipv4.dport = hw_entry->ipv4.dport;

	/*
	 * ppe->lock remains held, so the learned slot cannot be cleared or
	 * committed by another software path between authorization and BIND
	 * publication.
	 */
	ra_ppe_v1_foe_commit_locked(ppe, foe, &bind);

	entry->hash = foe;
	entry->hash_valid = true;
	WRITE_ONCE(entry->lastused, jiffies);

	ret = true;

out_unlock:
	spin_unlock_irqrestore(&ppe->lock, flags);
	rcu_read_unlock();

	return ret;
}

const struct ra_ppe_offload_ops ra_ppe_v1_offload_ops = {
	.prepare	= ra_ppe_v1_flow_prepare,
	.remove		= ra_ppe_v1_flow_remove,
	.check		= ra_ppe_v1_offload_check,
};
