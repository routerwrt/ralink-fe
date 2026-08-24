// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/dsa/8021q.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/rhashtable.h>
#include <linux/tcp.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/udp.h>

#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/ip.h>
#include <net/pkt_cls.h>

#include "ralink_fe.h"
#include "ra_ppe.h"
#include "ra_ppe_foe.h"
#include "ra_ppe_offload.h"
#include "ra_ppe_regs.h"

static const struct rhashtable_params ra_flow_ht_params = {
	.head_offset = offsetof(struct ra_flow_entry, cookie_node),
	.key_offset = offsetof(struct ra_flow_entry, cookie),
	.key_len = sizeof_field(struct ra_flow_entry, cookie),
	.automatic_shrinking = true,
};

static const struct rhashtable_params ra_flow_tuple_ht_params = {
	.head_offset = offsetof(struct ra_flow_entry, tuple_node),
	.key_offset = offsetof(struct ra_flow_entry, key),
	.key_len = sizeof_field(struct ra_flow_entry, key),
	.automatic_shrinking = true,
};

static void
ra_flow_key_from_foe(struct ra_flow_key *key,
		     const struct ra_foe_entry *foe)
{
	const struct ra_foe_ipv4_hnapt *hnapt = &foe->ipv4_hnapt;
	u32 ib1 = READ_ONCE(foe->info_blk1);

	*key = (struct ra_flow_key) {
		.src = htonl(hnapt->sip),
		.dst = htonl(hnapt->dip),
		.sport = htons(hnapt->sport),
		.dport = htons(hnapt->dport),
		.proto = (ib1 & RA_FOE_IB1_UDP) ?
			 IPPROTO_UDP : IPPROTO_TCP,
	};
}

static bool
ra_flow_foe_matches(const struct ra_foe_entry *foe,
		    const struct ra_flow_key *key)
{
	struct ra_flow_key foe_key;

	ra_flow_key_from_foe(&foe_key, foe);

	return !memcmp(&foe_key, key, sizeof(foe_key));
}

static bool
ra_flow_foe_is_bound(const struct ra_foe_entry *foe,
		     const struct ra_flow_key *key)
{
	if (ra_foe_state(foe) != RA_FOE_STATE_BIND)
		return false;

	dma_rmb();

	if (!ra_foe_is_ipv4_hnapt(foe))
		return false;

	return ra_flow_foe_matches(foe, key);
}

static int
ra_flow_mangle_eth(const struct flow_action_entry *act,
		   struct ra_flow_data *data)
{
	const u8 *val = (const u8 *)&act->mangle.val;

	/*
	 * nf_flow_table emits Ethernet mangles as 32-bit pedit operations:
	 *
	 * destination:
	 *	offset 0, replace all 4 bytes
	 *	offset 4, replace low 2 bytes
	 *
	 * source:
	 *	offset 4, replace high 2 bytes
	 *	offset 8, replace all 4 bytes
	 *
	 * Only accept these exact forms. Silently accepting another pedit
	 * mask would make the hardware rule differ from the flower rule.
	 */
	switch (act->mangle.offset) {
	case 0:
		if (act->mangle.mask)
			return -EOPNOTSUPP;

		memcpy(data->eth.h_dest, val, 4);
		return 0;

	case 4:
		if (act->mangle.mask == ~0x0000ffffU) {
			memcpy(data->eth.h_dest + 4, val, 2);
			return 0;
		}

		if (act->mangle.mask == ~0xffff0000U) {
			memcpy(data->eth.h_source, val + 2, 2);
			return 0;
		}

		return -EOPNOTSUPP;

	case 8:
		if (act->mangle.mask)
			return -EOPNOTSUPP;

		memcpy(data->eth.h_source + 2, val, 4);
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}

static int
ra_flow_mangle_ipv4(const struct flow_action_entry *act,
		    struct ra_flow_data *data)
{
	/*
	 * pedit uses an inverted mask. A complete 32-bit replacement
	 * therefore has mask == 0.
	 */
	if (act->mangle.mask)
		return -EOPNOTSUPP;

	switch (act->mangle.offset) {
	case offsetof(struct iphdr, saddr):
		memcpy(&data->new_src_addr, &act->mangle.val,
		       sizeof(data->new_src_addr));
		return 0;

	case offsetof(struct iphdr, daddr):
		memcpy(&data->new_dst_addr, &act->mangle.val,
		       sizeof(data->new_dst_addr));
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}

static int
ra_flow_mangle_ports(const struct flow_action_entry *act,
		     struct ra_flow_data *data)
{
	u32 val;

	/*
	 * nf_flow_table emits source/destination port mangles at offset 0
	 * using one half of the 32-bit TCP/UDP source+destination word.
	 */
	if (act->mangle.offset)
		return -EOPNOTSUPP;

	val = ntohl(act->mangle.val);

	if (act->mangle.mask == ~htonl(0xffff0000)) {
		data->new_src_port = cpu_to_be16(val >> 16);
		return 0;
	}

	if (act->mangle.mask == ~htonl(0x0000ffff)) {
		data->new_dst_port = cpu_to_be16(val);
		return 0;
	}

	return -EOPNOTSUPP;
}

static void ra_flow_init_nat_defaults(struct ra_flow_data *data)
{
	data->new_src_addr = data->src_addr;
	data->new_dst_addr = data->dst_addr;
	data->new_src_port = data->src_port;
	data->new_dst_port = data->dst_port;
}

static void
ra_flow_build_foe(struct ra_foe_entry *foe,
		  const struct ra_flow_data *data)
{
	memset(foe, 0, sizeof(*foe));

	/*
	 * PPEv1 HNAPT tuple fields are stored in CPU order. Keep flow_data
	 * and ra_flow_key in network order and convert only at the hardware
	 * descriptor boundary.
	 */
	foe->ipv4_hnapt.bfib1.pkt_type = data->type;
	foe->ipv4_hnapt.bfib1.udp =
		data->l4proto == IPPROTO_UDP;

	foe->ipv4_hnapt.sip = ntohl(data->src_addr);
	foe->ipv4_hnapt.dip = ntohl(data->dst_addr);
	foe->ipv4_hnapt.sport = ntohs(data->src_port);
	foe->ipv4_hnapt.dport = ntohs(data->dst_port);

	foe->ipv4_hnapt.new_sip = ntohl(data->new_src_addr);
	foe->ipv4_hnapt.new_dip = ntohl(data->new_dst_addr);
	foe->ipv4_hnapt.new_sport = ntohs(data->new_src_port);
	foe->ipv4_hnapt.new_dport = ntohs(data->new_dst_port);

	ra_foe_set_mac(foe->ipv4_hnapt.dmac_hi,
		       data->eth.h_dest);
	ra_foe_set_mac(foe->ipv4_hnapt.smac_hi,
		       data->eth.h_source);

	/*
	 * VLAN operations are already resolved to PPEv1 semantics by
	 * ra_flow_resolve_output(). VID 0 remains valid because operation
	 * presence is represented by the action, not by the VID value.
	 */
	foe->bfib1.v1 = data->vlan1_action;
	foe->bfib1.v2 = data->vlan2_action;

	if (data->vlan1_action == RA_PPE_ACT_INSERT ||
	    data->vlan1_action == RA_PPE_ACT_MODIFY)
		foe->ipv4_hnapt.vlan1 = data->vlan1;

	if (data->vlan2_action == RA_PPE_ACT_INSERT ||
	    data->vlan2_action == RA_PPE_ACT_MODIFY)
		foe->ipv4_hnapt.vlan2 = data->vlan2;

	/*
	 * flow_action has PPPOE_PUSH but no corresponding PPPOE_POP.
	 * PPEv1 DELETE is a no-op on an unencapsulated packet, so routed
	 * flows default to DELETE unless the output requires PPPoE.
	 */
	if (data->pppoe_push) {
		foe->bfib1.pppoe = RA_PPE_ACT_INSERT;
		foe->ipv4_hnapt.pppoe_id = data->pppoe_id;
	} else {
		foe->bfib1.pppoe = RA_PPE_ACT_DELETE;
	}

	foe->ipv4_hnapt.iblk2.fd = 1;
	foe->ipv4_hnapt.iblk2.dp = data->dp;

	foe->ipv4_hnapt.bfib1.snap = RA_PPE_ACT_NONE;
	foe->ipv4_hnapt.bfib1.ttl = 1;
	foe->ipv4_hnapt.bfib1.ka = 1;
	foe->ipv4_hnapt.bfib1.sta = 0;

	/*
	 * State and timestamp are deliberately not published here.
	 * ra_ppe_foe_commit_locked() adds the current timestamp and
	 * publishes the complete descriptor atomically as BIND.
	 */
	foe->ipv4_hnapt.bfib1.state = RA_FOE_STATE_INVALID;
}

static int
ra_flow_resolve_output(struct ra_ppe *ppe, struct ra_flow_data *data)
{
	struct dsa_port *dp;
	struct net_device *br;

	dp = dsa_port_from_netdev(data->out_dev);
	if (IS_ERR(dp)) {
		if (data->out_dev != ppe->fe->ndev)
			return -EOPNOTSUPP;

		data->dp = 1;

		/*
		 * Non-DSA path. Flower VLAN actions directly describe the
		 * PPEv1 VLAN operation.
		 *
		 * PPEv1 smart VLAN behavior allows:
		 *
		 *	POP + PUSH	-> MODIFY
		 *	PUSH		-> INSERT
		 *	POP		-> DELETE
		 *	none		-> NONE
		 */
		if (data->vlan_pop && data->vlan_push) {
			data->vlan1 = data->push_vid;
			data->vlan1_action = RA_PPE_ACT_MODIFY;
		} else if (data->vlan_push) {
			data->vlan1 = data->push_vid;
			data->vlan1_action = RA_PPE_ACT_INSERT;
		} else if (data->vlan_pop) {
			data->vlan1_action = RA_PPE_ACT_DELETE;
		} else {
			data->vlan1_action = RA_PPE_ACT_NONE;
		}

		return 0;
	}

	if (!dp->cpu_dp || !dp->cpu_dp->tag_ops ||
	    dp->cpu_dp->tag_ops->proto != DSA_TAG_PROTO_RALINK)
		return -EOPNOTSUPP;

	br = dsa_port_bridge_dev_get(dp);

	if (br && br_vlan_enabled(br)) {
		u16 pvid;
		int err;

		data->dp = 1;

		if (data->vlan_push) {
			data->vlan1 = data->push_vid;
			data->vlan1_action = data->vlan_pop ?
					     RA_PPE_ACT_MODIFY :
					     RA_PPE_ACT_INSERT;
			data->vlan2_action = RA_PPE_ACT_DELETE;
			return 0;
		}

		rcu_read_lock();
		err = br_vlan_get_pvid_rcu(br, &pvid);
		rcu_read_unlock();
		if (err)
			return err;

		data->vlan1 = pvid;
		data->vlan1_action = data->vlan_pop ?
				     RA_PPE_ACT_DELETE :
				     RA_PPE_ACT_INSERT;

		return 0;
	}

	if (br) {
		unsigned int bridge_num;

		bridge_num = dsa_port_bridge_num_get(dp);

		data->vlan1 = dsa_tag_8021q_bridge_vid(bridge_num);
		data->vlan1_action = RA_PPE_ACT_INSERT;
		data->dp = 1;

		return 0;
	}

	data->vlan1 = dsa_tag_8021q_standalone_vid(dp);
	data->vlan1_action = RA_PPE_ACT_INSERT;
	data->dp = 2;

	return 0;
}

static int
ra_flow_parse_match(struct flow_cls_offload *f,
		    struct ra_flow_data *data)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_ipv4_addrs ipv4;
	struct flow_match_control control;
	struct flow_match_basic basic;
	struct flow_match_ports ports;
	struct flow_match_meta meta;
	u64 supported_keys;

	supported_keys =
		BIT_ULL(FLOW_DISSECTOR_KEY_META) |
		BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
		BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
		BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_TCP);

	if (rule->match.dissector->used_keys & ~supported_keys) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported flower match key for PPEv1");
		return -EOPNOTSUPP;
	}

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 requires an exact IPv4 5-tuple");
		return -EOPNOTSUPP;
	}

	flow_rule_match_meta(rule, &meta);

	/*
	 * ingress_ifindex is part of the flower rule representation but is
	 * not part of the PPEv1 hardware flow key. Reject only metadata
	 * semantics that PPEv1 cannot represent.
	 */
	if (meta.mask->ingress_iftype || meta.mask->l2_miss) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported flower metadata for PPEv1");
		return -EOPNOTSUPP;
	}

	flow_rule_match_control(rule, &control);

	if (control.mask->addr_type != 0xffff ||
	    control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 supports IPv4 flows only");
		return -EOPNOTSUPP;
	}

	if (control.mask->thoff ||
	    flow_rule_has_control_flags(control.mask->flags,
					f->common.extack))
		return -EOPNOTSUPP;

	flow_rule_match_basic(rule, &basic);

	if (basic.mask->n_proto != htons(0xffff) ||
	    basic.key->n_proto != htons(ETH_P_IP) ||
	    basic.mask->ip_proto != 0xff) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 requires exact IPv4 protocol matching");
		return -EOPNOTSUPP;
	}

	data->l4proto = basic.key->ip_proto;

	if (data->l4proto != IPPROTO_TCP &&
	    data->l4proto != IPPROTO_UDP) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 supports TCP and UDP only");
		return -EOPNOTSUPP;
	}

	flow_rule_match_ipv4_addrs(rule, &ipv4);

	if (ipv4.mask->src != cpu_to_be32(~0U) ||
	    ipv4.mask->dst != cpu_to_be32(~0U)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 requires exact IPv4 address matches");
		return -EOPNOTSUPP;
	}

	data->src_addr = ipv4.key->src;
	data->dst_addr = ipv4.key->dst;

	flow_rule_match_ports(rule, &ports);

	if (ports.mask->src != cpu_to_be16(0xffff) ||
	    ports.mask->dst != cpu_to_be16(0xffff)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 requires exact transport port matches");
		return -EOPNOTSUPP;
	}

	data->src_port = ports.key->src;
	data->dst_port = ports.key->dst;

	/*
	 * nf_flow_table excludes FIN/RST from accelerated TCP flows.
	 * PPEv1 provides equivalent exceptional-packet handling through
	 * TCP_SYN_FIN_RST and HIT_FIN CPU reasons.
	 */
	if (data->l4proto == IPPROTO_TCP) {
		struct flow_match_tcp tcp;
		__be16 expected;

		if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "PPEv1 TCP offload requires FIN/RST exclusion");
			return -EOPNOTSUPP;
		}

		flow_rule_match_tcp(rule, &tcp);

		expected = cpu_to_be16(
			be32_to_cpu(TCP_FLAG_RST | TCP_FLAG_FIN) >> 16);

		if (tcp.key->flags || tcp.mask->flags != expected) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "Unsupported TCP flag match");
			return -EOPNOTSUPP;
		}
	} else if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "TCP flags supplied for a non-TCP flow");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
ra_flow_validate_csum(const struct flow_action_entry *act,
		      const struct ra_flow_data *data)
{
	u32 supported;

	supported = TCA_CSUM_UPDATE_FLAG_IPV4HDR;

	if (data->l4proto == IPPROTO_TCP)
		supported |= TCA_CSUM_UPDATE_FLAG_TCP;
	else
		supported |= TCA_CSUM_UPDATE_FLAG_UDP;

	if (act->csum_flags & ~supported)
		return -EOPNOTSUPP;

	/*
	 * PPEv1 HNAPT recalculates IPv4 and TCP/UDP checksums after tuple
	 * rewriting, so the corresponding software checksum action requires
	 * no additional FOE encoding.
	 */
	return 0;
}

static int
ra_flow_parse_actions(struct flow_cls_offload *f,
		      struct ra_flow_data *data)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_action_entry *act;
	bool csum_seen = false;
	int err;
	int i;

	if (!flow_action_has_entries(&rule->action)) {
		NL_SET_ERR_MSG_MOD(f->common.extack, "Flow has no actions");
		return -EINVAL;
	}

	/*
	 * lastused is maintained from PPE keepalive notifications, so this
	 * driver provides delayed rather than immediate hardware stats.
	 */
	if (!flow_action_hw_stats_check(&rule->action,
					f->common.extack,
					FLOW_ACTION_HW_STATS_DELAYED_BIT))
		return -EOPNOTSUPP;

	/*
	 * First pass: gather topology/encapsulation state and Ethernet
	 * rewrites. Output-device resolution is deliberately deferred until
	 * the complete action set is known.
	 */
	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			if (act->mangle.htype !=
			    FLOW_ACT_MANGLE_HDR_TYPE_ETH)
				break;

			err = ra_flow_mangle_eth(act, data);
			if (err)
				return err;
			break;

		case FLOW_ACTION_REDIRECT:
			if (!act->dev || data->out_dev) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "PPEv1 requires exactly one redirect");
				return -EOPNOTSUPP;
			}

			data->out_dev = act->dev;
			break;

		case FLOW_ACTION_CSUM:
			if (csum_seen) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Multiple checksum actions are unsupported");
				return -EOPNOTSUPP;
			}

			err = ra_flow_validate_csum(act, data);
			if (err)
				return err;

			csum_seen = true;
			break;

		case FLOW_ACTION_VLAN_PUSH:
			if (data->vlan_push ||
			    act->vlan.proto != htons(ETH_P_8021Q)) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Unsupported VLAN push");
				return -EOPNOTSUPP;
			}

			data->vlan_push = true;
			data->push_vid = act->vlan.vid;
			break;

		case FLOW_ACTION_VLAN_POP:
			if (data->vlan_pop) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Multiple VLAN pops are unsupported");
				return -EOPNOTSUPP;
			}

			data->vlan_pop = true;
			break;

		case FLOW_ACTION_PPPOE_PUSH:
			if (data->pppoe_push) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Multiple PPPoE pushes are unsupported");
				return -EOPNOTSUPP;
			}

			data->pppoe_push = true;
			data->pppoe_id = act->pppoe.sid;
			break;

		default:
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "Unsupported action for PPEv1");
			return -EOPNOTSUPP;
		}
	}

	if (!data->out_dev) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 requires a redirect action");
		return -EOPNOTSUPP;
	}

	/*
	 * Second pass: apply NAT rewrites after the original tuple has been
	 * completely established.
	 */
	flow_action_for_each(i, act, &rule->action) {
		if (act->id != FLOW_ACTION_MANGLE)
			continue;

		switch (act->mangle.htype) {
		case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
			/* Already handled above. */
			break;

		case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
			err = ra_flow_mangle_ipv4(act, data);
			if (err)
				return err;
			break;

		case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			if (data->l4proto != IPPROTO_TCP)
				return -EOPNOTSUPP;

			err = ra_flow_mangle_ports(act, data);
			if (err)
				return err;
			break;

		case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
			if (data->l4proto != IPPROTO_UDP)
				return -EOPNOTSUPP;

			err = ra_flow_mangle_ports(act, data);
			if (err)
				return err;
			break;

		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int
ra_ppe_flow_replace(struct ra_ppe *ppe, struct flow_cls_offload *f)
{
	struct ra_flow_entry *entry;
	struct ra_flow_data data = {};
	struct ra_foe_entry foe;
	int err;

	lockdep_assert_held(&ppe->flow_lock);

	if (f->common.chain_index) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPEv1 supports chain 0 only");
		return -EOPNOTSUPP;
	}

	if (rhashtable_lookup_fast(&ppe->flow_table, &f->cookie,
				   ra_flow_ht_params))
		return -EEXIST;

	err = ra_flow_parse_match(f, &data);
	if (err)
		return err;

	data.type = RA_FOE_IPV4_HNAPT;

	ra_flow_init_nat_defaults(&data);

	err = ra_flow_parse_actions(f, &data);
	if (err)
		return err;

	err = ra_flow_resolve_output(ppe, &data);
	if (err)
		return err;

	if (!is_valid_ether_addr(data.eth.h_source) ||
	    !is_valid_ether_addr(data.eth.h_dest)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Valid source and destination MAC rewrite required");
		return -EINVAL;
	}

	ra_flow_build_foe(&foe, &data);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->cookie = f->cookie;

	entry->key = (struct ra_flow_key) {
		.src = data.src_addr,
		.dst = data.dst_addr,
		.sport = data.src_port,
		.dport = data.dst_port,
		.proto = data.l4proto,
	};

	entry->bind = foe;

	/*
	 * Install the cookie entry first. flow_lock serializes control-path
	 * users, so this intermediate state is not visible to another TC
	 * command.
	 */
	err = rhashtable_insert_fast(&ppe->flow_table,
				     &entry->cookie_node,
				     ra_flow_ht_params);
	if (err)
		goto free;

	/*
	 * Publish to the RX-visible tuple table last.
	 *
	 * Once this succeeds, HIT_UNBIND_RATE_REACH may find the entry and
	 * promote a learned FOE slot to BIND. There must be no subsequent
	 * installation step which can fail and leave an orphaned BIND.
	 */
	err = rhashtable_insert_fast(&ppe->flow_tuple_table,
				     &entry->tuple_node,
				     ra_flow_tuple_ht_params);
	if (err)
		goto remove_cookie;

	return 0;

remove_cookie:
	rhashtable_remove_fast(&ppe->flow_table,
			       &entry->cookie_node,
			       ra_flow_ht_params);
free:
	kfree(entry);

	return err;
}

static void
ra_ppe_flow_remove(struct ra_ppe *ppe, struct ra_flow_entry *entry)
{
	unsigned long flags;

	lockdep_assert_held(&ppe->flow_lock);

	/*
	 * Serialize logical deletion and hardware removal against the RX
	 * path. An RCU reader may already hold a pointer obtained from the
	 * tuple table, so entry->dead prevents it from binding after the
	 * control path starts deletion.
	 */
	spin_lock_irqsave(&ppe->lock, flags);

	entry->dead = true;

	if (entry->hash_valid) {
		u16 hash = entry->hash;

		/*
		 * The remembered index may have aged out and been reused by
		 * hardware. Only clear it when it is still the BIND belonging
		 * to this software flow.
		 */
		if (hash < ppe->foe_entries &&
		    ra_flow_foe_is_bound(&ppe->foe_table[hash],
					 &entry->key))
			ra_ppe_foe_clear_locked(ppe, hash);

		entry->hash_valid = false;
	}

	spin_unlock_irqrestore(&ppe->lock, flags);

	/*
	 * Remove the RX-visible tuple mapping before removing the control
	 * path cookie. Existing readers remain protected by RCU and will
	 * observe entry->dead after taking ppe->lock.
	 */
	rhashtable_remove_fast(&ppe->flow_tuple_table,
			       &entry->tuple_node,
			       ra_flow_tuple_ht_params);

	rhashtable_remove_fast(&ppe->flow_table,
			       &entry->cookie_node,
			       ra_flow_ht_params);

	kfree_rcu(entry, rcu);
}

static int
ra_ppe_flow_destroy(struct ra_ppe *ppe, struct flow_cls_offload *f)
{
	struct ra_flow_entry *entry;

	lockdep_assert_held(&ppe->flow_lock);

	entry = rhashtable_lookup_fast(&ppe->flow_table, &f->cookie,
				       ra_flow_ht_params);
	if (!entry)
		return 0;

	ra_ppe_flow_remove(ppe, entry);

	return 0;
}

static int
ra_ppe_flow_stats(struct ra_ppe *ppe, struct flow_cls_offload *f)
{
	struct ra_flow_entry *entry;
	unsigned long lastused;

	lockdep_assert_held(&ppe->flow_lock);

	entry = rhashtable_lookup_fast(&ppe->flow_table, &f->cookie,
				       ra_flow_ht_params);
	if (!entry)
		return -ENOENT;

	lastused = READ_ONCE(entry->lastused);

	flow_stats_update(&f->stats, 0, 0, 0, lastused,
			  FLOW_ACTION_HW_STATS_DELAYED);

	return 0;
}

static int
ra_ppe_setup_tc_cls_flower(struct ra_ppe *ppe,
			   struct flow_cls_offload *f)
{
	int err;

	mutex_lock(&ppe->flow_lock);

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		err = ra_ppe_flow_replace(ppe, f);
		break;

	case FLOW_CLS_DESTROY:
		err = ra_ppe_flow_destroy(ppe, f);
		break;

	case FLOW_CLS_STATS:
		err = ra_ppe_flow_stats(ppe, f);
		break;

	default:
		err = -EOPNOTSUPP;
		break;
	}

	mutex_unlock(&ppe->flow_lock);

	return err;
}

static int
ra_ppe_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			 void *cb_priv)
{
	struct ra_ppe *ppe = cb_priv;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	return ra_ppe_setup_tc_cls_flower(ppe, type_data);
}

int
ra_ppe_setup_tc_block(struct ra_ppe *ppe, struct net_device *dev,
		      struct flow_block_offload *f)
{
	if (!ppe)
		return -EOPNOTSUPP;

	return flow_block_cb_setup_simple(f,
					  &ppe->flow_block_cb_list,
					  ra_ppe_setup_tc_block_cb,
					  dev, ppe, true);
}

int ra_ppe_offload_init(struct ra_ppe *ppe)
{
	int err;

	INIT_LIST_HEAD(&ppe->flow_block_cb_list);
	mutex_init(&ppe->flow_lock);

	err = rhashtable_init(&ppe->flow_table,
			      &ra_flow_ht_params);
	if (err)
		return err;

	err = rhashtable_init(&ppe->flow_tuple_table,
			      &ra_flow_tuple_ht_params);
	if (err) {
		rhashtable_destroy(&ppe->flow_table);
		return err;
	}

	return 0;
}

void ra_ppe_offload_reset(struct ra_ppe *ppe)
{
	struct rhashtable_iter iter;
	struct ra_flow_entry *entry;
	unsigned long flags;

	mutex_lock(&ppe->flow_lock);

	rhashtable_walk_enter(&ppe->flow_table, &iter);
	rhashtable_walk_start(&iter);

	for (;;) {
		entry = rhashtable_walk_next(&iter);
		if (!entry)
			break;

		if (IS_ERR(entry)) {
			if (PTR_ERR(entry) == -EAGAIN)
				continue;

			break;
		}

		spin_lock_irqsave(&ppe->lock, flags);

		/*
		 * Keep Linux's authorization, but forget its old hardware
		 * location. After restart the flow may be learned again and
		 * associated with a different FOE index.
		 */
		entry->hash_valid = false;

		spin_unlock_irqrestore(&ppe->lock, flags);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	mutex_unlock(&ppe->flow_lock);
}

static void ra_ppe_flow_flush(struct ra_ppe *ppe)
{
	struct rhashtable_iter iter;
	struct ra_flow_entry *entry;

	mutex_lock(&ppe->flow_lock);

	rhashtable_walk_enter(&ppe->flow_table, &iter);
	rhashtable_walk_start(&iter);

	for (;;) {
		entry = rhashtable_walk_next(&iter);
		if (!entry)
			break;

		if (IS_ERR(entry)) {
			if (PTR_ERR(entry) == -EAGAIN)
				continue;

			break;
		}

		ra_ppe_flow_remove(ppe, entry);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	mutex_unlock(&ppe->flow_lock);
}

void ra_ppe_offload_deinit(struct ra_ppe *ppe)
{
	ra_ppe_flow_flush(ppe);

	/*
	 * Final PPE teardown must happen after the FE RX/NAPI path has been
	 * quiesced. synchronize_rcu() additionally guarantees that no
	 * tuple-table reader still retains a removed ra_flow_entry.
	 */
	synchronize_rcu();

	rhashtable_destroy(&ppe->flow_tuple_table);
	rhashtable_destroy(&ppe->flow_table);
}

bool
ra_ppe_offload_check(struct ra_ppe *ppe, u16 foe, bool keepalive)
{
	struct ra_foe_entry *hw_entry;
	struct ra_flow_entry *entry;
	struct ra_foe_entry bind;
	struct ra_flow_key key;
	unsigned long flags;
	bool ret = false;

	if (!ppe || foe >= ppe->foe_entries)
		return false;

	/*
	 * tuple_table is read from RX/NAPI while the TC control path may
	 * remove entries. RCU protects ra_flow_entry lifetime; ppe->lock
	 * protects hardware association state and direct FOE access.
	 */
	rcu_read_lock();

	spin_lock_irqsave(&ppe->lock, flags);

	hw_entry = &ppe->foe_table[foe];

	if (keepalive) {
		/*
		 * A keepalive reason originates from a BIND entry.
		 */
		if (ra_foe_state(hw_entry) != RA_FOE_STATE_BIND)
			goto out_unlock;
	} else {
		/*
		 * Promotion is only valid for a hardware-learned UNBIND
		 * entry.
		 */
		if (!ra_foe_is_unbind(hw_entry))
			goto out_unlock;
	}

	/*
	 * The FOE table is coherent DMA memory. Coherency does not imply
	 * ordering: after observing the hardware-published state, order
	 * subsequent descriptor reads behind that observation.
	 */
	dma_rmb();

	if (!ra_foe_is_ipv4_hnapt(hw_entry))
		goto out_unlock;

	ra_flow_key_from_foe(&key, hw_entry);

	entry = rhashtable_lookup_fast(&ppe->flow_tuple_table,
				       &key,
				       ra_flow_tuple_ht_params);
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
	 * If software remembers a different FOE slot, only regard that
	 * association as still active if the slot remains a matching BIND.
	 * Otherwise the old hardware association has aged out or the slot
	 * has been reused and may be forgotten.
	 */
	if (entry->hash_valid && entry->hash != foe) {
		if (entry->hash < ppe->foe_entries &&
		    ra_flow_foe_is_bound(&ppe->foe_table[entry->hash],
					 &entry->key))
			goto out_unlock;

		entry->hash_valid = false;
	}

	bind = entry->bind;

	/*
	 * Preserve the exact original tuple learned by PPE. These fields are
	 * already in PPE hardware/CPU byte order.
	 */
	bind.ipv4_hnapt.sip = hw_entry->ipv4_hnapt.sip;
	bind.ipv4_hnapt.dip = hw_entry->ipv4_hnapt.dip;
	bind.ipv4_hnapt.sport = hw_entry->ipv4_hnapt.sport;
	bind.ipv4_hnapt.dport = hw_entry->ipv4_hnapt.dport;

	/*
	 * ppe->lock is still held, so the learned slot cannot be cleared or
	 * committed by another software path between authorization and final
	 * BIND publication.
	 */
	ra_ppe_foe_commit_locked(ppe, foe, &bind);

	entry->hash = foe;
	entry->hash_valid = true;
	WRITE_ONCE(entry->lastused, jiffies);

	ret = true;

out_unlock:
	spin_unlock_irqrestore(&ppe->lock, flags);
	rcu_read_unlock();

	return ret;
}
