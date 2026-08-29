/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_OFFLOAD_H
#define _RA_PPE_OFFLOAD_H

#include <linux/etherdevice.h>
#include <linux/in6.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>

#include <net/flow_offload.h>

struct ra_ppe;

/*
 * Keep the generic flow key independent of a PPE descriptor format.
 *
 * The complete object is used as an rhashtable key, so all fields,
 * including unused address-union bytes and pad, must be initialized.
 */
union ra_flow_addr {
	__be32 ipv4;
	struct in6_addr ipv6;
};

struct ra_flow_key {
	__be16 n_proto;
	u8 ip_proto;
	u8 pad;

	__be16 src_port;
	__be16 dst_port;

	union ra_flow_addr src;
	union ra_flow_addr dst;
};

/*
 * Hardware-independent software flow state.
 *
 * PPE-generation-specific flow objects must embed this as their first
 * member. This permits the generic layer to own rhashtable and RCU
 * lifetime management while the implementation attaches its private
 * hardware template after it.
 */
struct ra_flow_entry {
	struct rhash_head cookie_node;
	struct rhash_head tuple_node;
	struct rcu_head rcu;

	unsigned long cookie;
	struct ra_flow_key key;

	/*
	 * Hardware flow-table association.
	 *
	 * The interpretation of the index is implementation-specific, but
	 * its lifetime semantics are common.
	 */
	u16 hash;
	bool hash_valid;

	/* Protected by ppe->lock. */
	bool dead;

	unsigned long lastused;
};

/*
 * Logical VLAN operations requested by flower.
 *
 * These are deliberately not converted into PPE INSERT/DELETE/MODIFY
 * semantics here. Each PPE generation performs that translation.
 */
struct ra_flow_vlan {
	bool push;
	bool pop;

	__be16 push_proto;
	u16 push_vid;
	u8 push_prio;
};

/*
 * Logical PPPoE operation requested by flower.
 *
 * Do not infer an implicit PPE DELETE operation when push is false.
 * That is a hardware-generation policy decision.
 */
struct ra_flow_pppoe {
	bool push;
	u16 sid;
};

/*
 * Logical flow produced from the flower rule.
 *
 * This structure describes what Linux asked for. It must not contain
 * PPEv1/PPEv2 descriptor fields, destination-port encoding, VLAN slots,
 * FOE packet types, or similar hardware representation.
 */
struct ra_flow_data {
	struct ethhdr eth;

	__be16 n_proto;
	u8 l4proto;

	/*
	 * Original layer-3 tuple.
	 *
	 * For IPv4 only .ipv4 is significant.
	 * For IPv6 the complete .ipv6 member is significant.
	 */
	union ra_flow_addr src_addr;
	union ra_flow_addr dst_addr;

	/*
	 * Rewritten layer-3 tuple.
	 *
	 * Initialized from the original tuple before action parsing.
	 */
	union ra_flow_addr new_src_addr;
	union ra_flow_addr new_dst_addr;

	__be16 src_port;
	__be16 dst_port;

	__be16 new_src_port;
	__be16 new_dst_port;

	struct net_device *out_dev;

	struct ra_flow_vlan vlan;
	struct ra_flow_pppoe pppoe;
};

/*
 * Generation-specific translation between a logical Linux flow and the
 * hardware flow-table representation.
 */
struct ra_ppe_offload_ops {
	/*
	 * Validate generation-specific representability and allocate/build
	 * the private flow object.
	 *
	 * On success, *entry must point at the embedded struct ra_flow_entry
	 * which is the first member of that allocation.
	 */
	int (*prepare)(struct ra_ppe *ppe,
		       struct flow_cls_offload *f,
		       const struct ra_flow_data *data,
		       struct ra_flow_entry **entry);

	/*
	 * Remove any live hardware association for this software flow.
	 *
	 * Generic code owns rhashtable removal and RCU freeing.
	 * ppe->flow_lock is held when this callback is invoked.
	 */
	void (*remove)(struct ra_ppe *ppe,
		       struct ra_flow_entry *entry);

	/*
	 * Handle a hardware flow-table notification from RX.
	 */
	bool (*check)(struct ra_ppe *ppe, u16 index, bool keepalive);
};

int ra_ppe_setup_tc_block(struct ra_ppe *ppe,
			  struct net_device *dev,
			  struct flow_block_offload *f);

int ra_ppe_offload_init(struct ra_ppe *ppe);
void ra_ppe_offload_reset(struct ra_ppe *ppe);
void ra_ppe_offload_deinit(struct ra_ppe *ppe);

struct ra_flow_entry *
ra_ppe_flow_lookup_cookie(struct ra_ppe *ppe, unsigned long cookie);

struct ra_flow_entry *
ra_ppe_flow_lookup_tuple(struct ra_ppe *ppe,
			 const struct ra_flow_key *key);

extern const struct ra_ppe_offload_ops ra_ppe_v1_offload_ops;

#endif
