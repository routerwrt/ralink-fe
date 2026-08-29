// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/dsa/8021q.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>

#include "ralink_fe.h"
#include "ra_ppe.h"
#include "ra_ppe_foe.h"
#include "ra_ppe_offload.h"
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
	struct ra_foe_entry bind;
};

struct ra_ppe_v1_output {
	u16 vlan1;
	u16 vlan2;

	enum ra_ppe_action vlan1_action;
	enum ra_ppe_action vlan2_action;

	bool pppoe;
	u16 pppoe_id;

	u8 dp;
};

static inline struct ra_ppe_v1_flow_entry *
ra_ppe_v1_flow_entry(struct ra_flow_entry *flow)
{
	return container_of(flow, struct ra_ppe_v1_flow_entry, flow);
}

static void
ra_ppe_v1_flow_key_from_foe(struct ra_flow_key *key,
			    const struct ra_foe_entry *foe)
{
	const struct ra_foe_ipv4_hnapt *hnapt = &foe->ipv4_hnapt;
	u32 ib1 = READ_ONCE(foe->info_blk1);

	memset(key, 0, sizeof(*key));

	key->n_proto = htons(ETH_P_IP);
	key->ip_proto = (ib1 & RA_FOE_IB1_UDP) ?
			IPPROTO_UDP : IPPROTO_TCP;

	key->src_port = htons(hnapt->sport);
	key->dst_port = htons(hnapt->dport);

	key->src.ipv4 = htonl(hnapt->sip);
	key->dst.ipv4 = htonl(hnapt->dip);
}

static bool
ra_ppe_v1_flow_foe_matches(const struct ra_foe_entry *foe,
			   const struct ra_flow_key *key)
{
	struct ra_flow_key foe_key;

	ra_ppe_v1_flow_key_from_foe(&foe_key, foe);

	return !memcmp(&foe_key, key, sizeof(foe_key));
}

static bool
ra_ppe_v1_flow_foe_is_bound(const struct ra_foe_entry *foe,
			    const struct ra_flow_key *key)
{
	if (ra_foe_state(foe) != RA_FOE_STATE_BIND)
		return false;

	dma_rmb();

	if (!ra_foe_is_ipv4_hnapt(foe))
		return false;

	return ra_ppe_v1_flow_foe_matches(foe, key);
}

static inline struct ra_foe_entry *
ra_ppe_v1_foe_entry(struct ra_ppe *ppe, u32 index)
{
	return (struct ra_foe_entry *)ppe->foe_table + index;
}

static void
ra_ppe_v1_foe_commit_locked(struct ra_ppe *ppe, u32 index,
			    const struct ra_foe_entry *entry)
{
	struct ra_foe_entry bind;
	struct ra_foe_entry *dst;
	u32 ib1, final_ib1;
	u16 timestamp;

	lockdep_assert_held(&ppe->lock);

	if (WARN_ON_ONCE(index >= ppe->foe_entries))
		return;

	bind = *entry;

	timestamp = ra_ppe_r32(ppe, RA_REG_FOE_TS) & 0xffff;

	ib1 = bind.info_blk1;
	ib1 &= ~(RA_FOE_IB1_BIND_TIMESTAMP |
		 RA_FOE_IB1_TTL |
		 RA_FOE_IB1_STATE);

	ib1 |= FIELD_PREP(RA_FOE_IB1_BIND_TIMESTAMP, timestamp);
	ib1 |= RA_FOE_IB1_TTL;
	ib1 |= FIELD_PREP(RA_FOE_IB1_STATE, RA_FOE_STATE_BIND);

	final_ib1 = ib1;

	bind.info_blk1 =
		(final_ib1 & ~RA_FOE_IB1_STATE) |
		FIELD_PREP(RA_FOE_IB1_STATE, RA_FOE_STATE_INVALID);

	dst = ra_ppe_v1_foe_entry(ppe, index);

	memcpy(dst, &bind, sizeof(*dst));

	dma_wmb();

	WRITE_ONCE(dst->info_blk1, final_ib1);
}

static void
ra_ppe_v1_foe_clear_locked(struct ra_ppe *ppe, u32 index)
{
	struct ra_foe_entry *foe;

	lockdep_assert_held(&ppe->lock);

	if (WARN_ON_ONCE(index >= ppe->foe_entries))
		return;

	foe = ra_ppe_v1_foe_entry(ppe, index);

	/*
	 * PPEv1 invalidation protocol.
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
		 * Translate the logical flower operation into PPEv1 smart-VLAN
		 * semantics.
		 */
		if (data->vlan.pop && data->vlan.push) {
			out->vlan1 = data->vlan.push_vid;
			out->vlan1_action = RA_PPE_ACT_MODIFY;
		} else if (data->vlan.push) {
			out->vlan1 = data->vlan.push_vid;
			out->vlan1_action = RA_PPE_ACT_INSERT;
		} else if (data->vlan.pop) {
			out->vlan1_action = RA_PPE_ACT_DELETE;
		} else {
			out->vlan1_action = RA_PPE_ACT_NONE;
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
					    RA_PPE_ACT_MODIFY :
					    RA_PPE_ACT_INSERT;

			out->vlan2_action = RA_PPE_ACT_DELETE;
			goto pppoe;
		}

		rcu_read_lock();
		err = br_vlan_get_pvid_rcu(br, &pvid);
		rcu_read_unlock();
		if (err)
			return err;

		out->vlan1 = pvid;
		out->vlan1_action = data->vlan.pop ?
				    RA_PPE_ACT_DELETE :
				    RA_PPE_ACT_INSERT;

		goto pppoe;
	}

	if (br) {
		unsigned int bridge_num;

		bridge_num = dsa_port_bridge_num_get(dp);

		out->vlan1 = dsa_tag_8021q_bridge_vid(bridge_num);
		out->vlan1_action = RA_PPE_ACT_INSERT;
		out->dp = 1;

		goto pppoe;
	}

	out->vlan1 = dsa_tag_8021q_standalone_vid(dp);
	out->vlan1_action = RA_PPE_ACT_INSERT;
	out->dp = 2;

pppoe:
	/*
	 * Keep PPPoE translation PPEv1-local. The generic flow merely says
	 * whether Linux requested a PPPOE_PUSH action.
	 */
	if (data->pppoe.push) {
		out->pppoe = true;
		out->pppoe_id = data->pppoe.sid;
	}

	return 0;
}

static void
ra_ppe_v1_build_foe(struct ra_foe_entry *foe,
		    const struct ra_flow_data *data,
		    const struct ra_ppe_v1_output *out)
{
	memset(foe, 0, sizeof(*foe));

	foe->ipv4_hnapt.bfib1.pkt_type = RA_FOE_IPV4_HNAPT;
	foe->ipv4_hnapt.bfib1.udp =
		data->l4proto == IPPROTO_UDP;

	/*
	 * PPEv1 IPv4 HNAPT tuple fields are stored in CPU order.
	 */
	foe->ipv4_hnapt.sip = ntohl(data->src_addr.ipv4);
	foe->ipv4_hnapt.dip = ntohl(data->dst_addr.ipv4);
	foe->ipv4_hnapt.sport = ntohs(data->src_port);
	foe->ipv4_hnapt.dport = ntohs(data->dst_port);

	foe->ipv4_hnapt.new_sip = ntohl(data->new_src_addr.ipv4);
	foe->ipv4_hnapt.new_dip = ntohl(data->new_dst_addr.ipv4);
	foe->ipv4_hnapt.new_sport = ntohs(data->new_src_port);
	foe->ipv4_hnapt.new_dport = ntohs(data->new_dst_port);

	ra_foe_set_mac(foe->ipv4_hnapt.dmac_hi,
		       data->eth.h_dest);
	ra_foe_set_mac(foe->ipv4_hnapt.smac_hi,
		       data->eth.h_source);

	foe->bfib1.v1 = out->vlan1_action;
	foe->bfib1.v2 = out->vlan2_action;

	if (out->vlan1_action == RA_PPE_ACT_INSERT ||
	    out->vlan1_action == RA_PPE_ACT_MODIFY)
		foe->ipv4_hnapt.vlan1 = out->vlan1;

	if (out->vlan2_action == RA_PPE_ACT_INSERT ||
	    out->vlan2_action == RA_PPE_ACT_MODIFY)
		foe->ipv4_hnapt.vlan2 = out->vlan2;

	/*
	 * PPEv1 DELETE is harmless for an unencapsulated routed packet, so
	 * retain the existing PPEv1 policy here rather than expressing it
	 * in the generic flow parser.
	 */
	if (out->pppoe) {
		foe->bfib1.pppoe = RA_PPE_ACT_INSERT;
		foe->ipv4_hnapt.pppoe_id = out->pppoe_id;
	} else {
		foe->bfib1.pppoe = RA_PPE_ACT_DELETE;
	}

	foe->ipv4_hnapt.iblk2.fd = 1;
	foe->ipv4_hnapt.iblk2.dp = out->dp;

	foe->ipv4_hnapt.bfib1.snap = RA_PPE_ACT_NONE;
	foe->ipv4_hnapt.bfib1.ttl = 1;
	foe->ipv4_hnapt.bfib1.ka = 1;
	foe->ipv4_hnapt.bfib1.sta = 0;

	/*
	 * State/timestamp are supplied by ra_ppe_v1_foe_commit_locked().
	 */
	foe->ipv4_hnapt.bfib1.state = RA_FOE_STATE_INVALID;
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
	 * The generic parser understands IPv6 so PPEv2 can use it later,
	 * but PPEv1's implementation remains strictly IPv4 HNAPT.
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
		 * Hardware may already have aged/reused the remembered slot.
		 * Clear only a BIND entry which still belongs to this flow.
		 */
		if (hash < ppe->foe_entries &&
		    ra_ppe_v1_flow_foe_is_bound(ra_ppe_v1_foe_entry(ppe, hash),
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
	struct ra_foe_entry *hw_entry;
	struct ra_flow_entry *entry;
	struct ra_foe_entry bind;
	struct ra_flow_key key;
	unsigned long flags;
	bool ret = false;

	if (!ppe || foe >= ppe->foe_entries)
		return false;

	rcu_read_lock();

	spin_lock_irqsave(&ppe->lock, flags);

	hw_entry = ra_ppe_v1_foe_entry(ppe, foe);

	if (keepalive) {
		if (ra_foe_state(hw_entry) != RA_FOE_STATE_BIND)
			goto out_unlock;
	} else {
		if (!ra_foe_is_unbind(hw_entry))
			goto out_unlock;
	}

	dma_rmb();

	if (!ra_foe_is_ipv4_hnapt(hw_entry))
		goto out_unlock;

	ra_ppe_v1_flow_key_from_foe(&key, hw_entry);

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
	 * A remembered different association remains authoritative while
	 * that slot is still a matching PPEv1 BIND.
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
	 * Preserve the exact original tuple learned by PPEv1.
	 */
	bind.ipv4_hnapt.sip = hw_entry->ipv4_hnapt.sip;
	bind.ipv4_hnapt.dip = hw_entry->ipv4_hnapt.dip;
	bind.ipv4_hnapt.sport = hw_entry->ipv4_hnapt.sport;
	bind.ipv4_hnapt.dport = hw_entry->ipv4_hnapt.dport;

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
