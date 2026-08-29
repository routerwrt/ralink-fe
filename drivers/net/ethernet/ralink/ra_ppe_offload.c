// SPDX-License-Identifier: GPL-2.0

#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <linux/tcp.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/udp.h>

#include <net/flow_offload.h>
#include <net/pkt_cls.h>

#include "ra_ppe.h"
#include "ra_ppe_offload.h"

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

struct ra_flow_entry *
ra_ppe_flow_lookup_cookie(struct ra_ppe *ppe, unsigned long cookie)
{
	return rhashtable_lookup_fast(&ppe->flow_table, &cookie,
				      ra_flow_ht_params);
}

struct ra_flow_entry *
ra_ppe_flow_lookup_tuple(struct ra_ppe *ppe,
			 const struct ra_flow_key *key)
{
	return rhashtable_lookup_fast(&ppe->flow_tuple_table, key,
				      ra_flow_tuple_ht_params);
}

static void
ra_flow_init_nat_defaults(struct ra_flow_data *data)
{
	data->new_src_addr = data->src_addr;
	data->new_dst_addr = data->dst_addr;

	data->new_src_port = data->src_port;
	data->new_dst_port = data->dst_port;
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
	if (data->n_proto != htons(ETH_P_IP))
		return -EOPNOTSUPP;

	/*
	 * pedit uses an inverted mask. A complete 32-bit replacement
	 * therefore has mask == 0.
	 */
	if (act->mangle.mask)
		return -EOPNOTSUPP;

	switch (act->mangle.offset) {
	case offsetof(struct iphdr, saddr):
		memcpy(&data->new_src_addr.ipv4, &act->mangle.val,
		       sizeof(data->new_src_addr.ipv4));
		return 0;

	case offsetof(struct iphdr, daddr):
		memcpy(&data->new_dst_addr.ipv4, &act->mangle.val,
		       sizeof(data->new_dst_addr.ipv4));
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

static int
ra_flow_parse_match(struct flow_cls_offload *f,
		    struct ra_flow_data *data)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
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
		BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_TCP);

	if (rule->match.dissector->used_keys & ~supported_keys) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported flower match key for PPE");
		return -EOPNOTSUPP;
	}

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE requires an exact IP 5-tuple");
		return -EOPNOTSUPP;
	}

	flow_rule_match_meta(rule, &meta);

	/*
	 * ingress_ifindex is part of the flower representation but does not
	 * form part of the hardware flow tuple.
	 */
	if (meta.mask->ingress_iftype || meta.mask->l2_miss) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported flower metadata for PPE");
		return -EOPNOTSUPP;
	}

	flow_rule_match_control(rule, &control);

	if (control.mask->addr_type != 0xffff) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE requires an exact address family");
		return -EOPNOTSUPP;
	}

	if (control.mask->thoff ||
	    flow_rule_has_control_flags(control.mask->flags,
					f->common.extack))
		return -EOPNOTSUPP;

	flow_rule_match_basic(rule, &basic);

	if (basic.mask->n_proto != htons(0xffff) ||
	    basic.mask->ip_proto != 0xff) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE requires exact protocol matching");
		return -EOPNOTSUPP;
	}

	data->n_proto = basic.key->n_proto;
	data->l4proto = basic.key->ip_proto;

	if (data->l4proto != IPPROTO_TCP &&
	    data->l4proto != IPPROTO_UDP) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE supports TCP and UDP flows only");
		return -EOPNOTSUPP;
	}

	switch (data->n_proto) {
	case htons(ETH_P_IP): {
		struct flow_match_ipv4_addrs ipv4;

		if (control.key->addr_type !=
		    FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
		    !flow_rule_match_key(rule,
					 FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "Invalid IPv4 flower address match");
			return -EOPNOTSUPP;
		}

		flow_rule_match_ipv4_addrs(rule, &ipv4);

		if (ipv4.mask->src != cpu_to_be32(~0U) ||
		    ipv4.mask->dst != cpu_to_be32(~0U)) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "PPE requires exact IPv4 address matches");
			return -EOPNOTSUPP;
		}

		data->src_addr.ipv4 = ipv4.key->src;
		data->dst_addr.ipv4 = ipv4.key->dst;
		break;
	}

	case htons(ETH_P_IPV6): {
		struct flow_match_ipv6_addrs ipv6;

		if (control.key->addr_type !=
		    FLOW_DISSECTOR_KEY_IPV6_ADDRS ||
		    !flow_rule_match_key(rule,
					 FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "Invalid IPv6 flower address match");
			return -EOPNOTSUPP;
		}

		flow_rule_match_ipv6_addrs(rule, &ipv6);

		if (memchr_inv(&ipv6.mask->src, 0xff,
			       sizeof(ipv6.mask->src)) ||
		    memchr_inv(&ipv6.mask->dst, 0xff,
			       sizeof(ipv6.mask->dst))) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "PPE requires exact IPv6 address matches");
			return -EOPNOTSUPP;
		}

		data->src_addr.ipv6 = ipv6.key->src;
		data->dst_addr.ipv6 = ipv6.key->dst;
		break;
	}

	default:
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported network protocol for PPE");
		return -EOPNOTSUPP;
	}

	flow_rule_match_ports(rule, &ports);

	if (ports.mask->src != cpu_to_be16(0xffff) ||
	    ports.mask->dst != cpu_to_be16(0xffff)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE requires exact transport port matches");
		return -EOPNOTSUPP;
	}

	data->src_port = ports.key->src;
	data->dst_port = ports.key->dst;

	if (data->l4proto == IPPROTO_TCP) {
		struct flow_match_tcp tcp;
		__be16 expected;

		if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "PPE TCP offload requires FIN/RST exclusion");
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
	u32 supported = 0;

	if (data->n_proto == htons(ETH_P_IP))
		supported |= TCA_CSUM_UPDATE_FLAG_IPV4HDR;

	if (data->l4proto == IPPROTO_TCP)
		supported |= TCA_CSUM_UPDATE_FLAG_TCP;
	else
		supported |= TCA_CSUM_UPDATE_FLAG_UDP;

	if (act->csum_flags & ~supported)
		return -EOPNOTSUPP;

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

	if (!flow_action_hw_stats_check(&rule->action,
					f->common.extack,
					FLOW_ACTION_HW_STATS_DELAYED_BIT))
		return -EOPNOTSUPP;

	/*
	 * First pass gathers logical topology/encapsulation state and L2
	 * rewrites. Hardware-specific output resolution happens later.
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
						   "PPE requires exactly one redirect");
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
			if (data->vlan.push) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Multiple VLAN pushes are unsupported");
				return -EOPNOTSUPP;
			}

			data->vlan.push = true;
			data->vlan.push_proto = act->vlan.proto;
			data->vlan.push_vid = act->vlan.vid;
			data->vlan.push_prio = act->vlan.prio;
			break;

		case FLOW_ACTION_VLAN_POP:
			if (data->vlan.pop) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Multiple VLAN pops are unsupported");
				return -EOPNOTSUPP;
			}

			data->vlan.pop = true;
			break;

		case FLOW_ACTION_PPPOE_PUSH:
			if (data->pppoe.push) {
				NL_SET_ERR_MSG_MOD(f->common.extack,
						   "Multiple PPPoE pushes are unsupported");
				return -EOPNOTSUPP;
			}

			data->pppoe.push = true;
			data->pppoe.sid = act->pppoe.sid;
			break;

		default:
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "Unsupported action for PPE");
			return -EOPNOTSUPP;
		}
	}

	if (!data->out_dev) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE requires a redirect action");
		return -EOPNOTSUPP;
	}

	/*
	 * Apply L3/L4 mangles only after the complete original tuple has
	 * been established.
	 */
	flow_action_for_each(i, act, &rule->action) {
		if (act->id != FLOW_ACTION_MANGLE)
			continue;

		switch (act->mangle.htype) {
		case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
			break;

		case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
			err = ra_flow_mangle_ipv4(act, data);
			if (err)
				return err;
			break;

		case FLOW_ACT_MANGLE_HDR_TYPE_IP6:
			/*
			 * Keep IPv6 in the generic flow representation now,
			 * but add 128-bit pedit reconstruction when PPEv2
			 * IPv6 NAT/mangle support is implemented.
			 */
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "IPv6 address mangles are not supported yet");
			return -EOPNOTSUPP;

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

static void
ra_flow_key_from_data(struct ra_flow_key *key,
		      const struct ra_flow_data *data)
{
	memset(key, 0, sizeof(*key));

	key->n_proto = data->n_proto;
	key->ip_proto = data->l4proto;
	key->src_port = data->src_port;
	key->dst_port = data->dst_port;

	key->src = data->src_addr;
	key->dst = data->dst_addr;
}

static int
ra_ppe_flow_insert(struct ra_ppe *ppe, struct ra_flow_entry *entry)
{
	int err;

	lockdep_assert_held(&ppe->flow_lock);

	err = rhashtable_insert_fast(&ppe->flow_table,
				     &entry->cookie_node,
				     ra_flow_ht_params);
	if (err)
		return err;

	/*
	 * Publish to the RX-visible tuple table last.
	 *
	 * Once this succeeds, a hardware notification may find the flow.
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

	return err;
}

static void
ra_ppe_flow_unlink(struct ra_ppe *ppe, struct ra_flow_entry *entry)
{
	lockdep_assert_held(&ppe->flow_lock);

	rhashtable_remove_fast(&ppe->flow_tuple_table,
			       &entry->tuple_node,
			       ra_flow_tuple_ht_params);

	rhashtable_remove_fast(&ppe->flow_table,
			       &entry->cookie_node,
			       ra_flow_ht_params);
}

static int
ra_ppe_flow_replace(struct ra_ppe *ppe, struct flow_cls_offload *f)
{
	const struct ra_ppe_offload_ops *ops = ppe->ops->offload;
	struct ra_flow_entry *entry;
	struct ra_flow_data data = {};
	int err;

	lockdep_assert_held(&ppe->flow_lock);

	if (f->common.chain_index) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "PPE supports chain 0 only");
		return -EOPNOTSUPP;
	}

	if (ra_ppe_flow_lookup_cookie(ppe, f->cookie))
		return -EEXIST;

	err = ra_flow_parse_match(f, &data);
	if (err)
		return err;

	ra_flow_init_nat_defaults(&data);

	err = ra_flow_parse_actions(f, &data);
	if (err)
		return err;

	if (!is_valid_ether_addr(data.eth.h_source) ||
	    !is_valid_ether_addr(data.eth.h_dest)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Valid source and destination MAC rewrite required");
		return -EINVAL;
	}

	err = ops->prepare(ppe, f, &data, &entry);
	if (err)
		return err;

	entry->cookie = f->cookie;
	ra_flow_key_from_data(&entry->key, &data);

	err = ra_ppe_flow_insert(ppe, entry);
	if (err)
		kfree(entry);

	return err;
}

static int
ra_ppe_flow_destroy(struct ra_ppe *ppe, struct flow_cls_offload *f)
{
	const struct ra_ppe_offload_ops *ops = ppe->ops->offload;
	struct ra_flow_entry *entry;

	lockdep_assert_held(&ppe->flow_lock);

	entry = ra_ppe_flow_lookup_cookie(ppe, f->cookie);
	if (!entry)
		return 0;

	/*
	 * Prevent an RX reader which already obtained this entry from
	 * creating a new hardware association.
	 */
	spin_lock_bh(&ppe->lock);
	entry->dead = true;
	spin_unlock_bh(&ppe->lock);

	if (ops->remove)
		ops->remove(ppe, entry);

	ra_ppe_flow_unlink(ppe, entry);

	kfree_rcu(entry, rcu);

	return 0;
}

static int
ra_ppe_flow_stats(struct ra_ppe *ppe, struct flow_cls_offload *f)
{
	struct ra_flow_entry *entry;
	unsigned long lastused;

	lockdep_assert_held(&ppe->flow_lock);

	entry = ra_ppe_flow_lookup_cookie(ppe, f->cookie);
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
	if (!ppe || !ppe->ops || !ppe->ops->offload)
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

	err = rhashtable_init(&ppe->flow_table, &ra_flow_ht_params);
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

		entry->dead = true;

		ra_ppe_flow_unlink(ppe, entry);
		kfree_rcu(entry, rcu);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	mutex_unlock(&ppe->flow_lock);
}

void ra_ppe_offload_deinit(struct ra_ppe *ppe)
{
	ra_ppe_flow_flush(ppe);

	synchronize_rcu();

	rhashtable_destroy(&ppe->flow_tuple_table);
	rhashtable_destroy(&ppe->flow_table);
}
