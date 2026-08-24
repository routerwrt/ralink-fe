/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_OFFLOAD_H
#define _RA_PPE_OFFLOAD_H

#include <linux/etherdevice.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>

#include <net/flow_offload.h>

#include "ra_ppe.h"
#include "ra_ppe_foe.h"

/*
 * Exact IPv4 5-tuple authorized for hardware offload.
 *
 * Keep this structure free of implicit/uninitialized padding because it
 * is used directly as an rhashtable key.
 */
struct ra_flow_key {
	__be32 src;
	__be32 dst;
	__be16 sport;
	__be16 dport;
	u8 proto;
	u8 pad[3];
};

struct ra_flow_entry {
	struct rhash_head cookie_node;
	struct rhash_head tuple_node;
	struct rcu_head rcu;

	unsigned long cookie;
	struct ra_flow_key key;

	u16 hash;
	bool hash_valid;

	/* Protected by ppe->lock. */
	bool dead;

	unsigned long lastused;

	/*
	 * Immutable BIND template after publication. RX copies it before
	 * filling learned tuple fields and committing the FOE entry.
	 */
	struct ra_foe_entry bind;
};

struct ra_flow_data {
	struct ethhdr eth;

	/* Original tuple from the flower match. */
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;

	/* Rewritten tuple after NAT mangles. */
	__be32 new_src_addr;
	__be32 new_dst_addr;
	__be16 new_src_port;
	__be16 new_dst_port;

	struct net_device *out_dev;

	/*
	 * Parsed flower encapsulation actions.
	 *
	 * Do not use VID == 0 as a presence indicator: VID 0 is valid for
	 * priority-tagged traffic.
	 */
	bool vlan_push;
	bool vlan_pop;
	u16 push_vid;

	bool pppoe_push;
	u16 pppoe_id;

	/*
	 * Final PPEv1 VLAN rewrite state, resolved after parsing the
	 * flower actions and output topology.
	 */
	u16 vlan1;
	u16 vlan2;
	enum ra_ppe_action vlan1_action;
	enum ra_ppe_action vlan2_action;

	u8 dp;
	u8 l4proto;
	u8 type;
};

int ra_ppe_setup_tc_block(struct ra_ppe *ppe,
			  struct net_device *dev,
			  struct flow_block_offload *f);

int ra_ppe_offload_init(struct ra_ppe *ppe);
void ra_ppe_offload_reset(struct ra_ppe *ppe);
void ra_ppe_offload_deinit(struct ra_ppe *ppe);

bool ra_ppe_offload_check(struct ra_ppe *ppe, u16 foe, bool keepalive);

#endif
