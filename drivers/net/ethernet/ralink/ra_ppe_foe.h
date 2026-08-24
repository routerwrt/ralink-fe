/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_FOE_H
#define _RA_PPE_FOE_H

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#define RA_FOE_ENTRY_SIZE	64

enum ra_foe_state {
	RA_FOE_STATE_INVALID = 0,
	RA_FOE_STATE_UNBIND  = 1,
	RA_FOE_STATE_BIND    = 2,
	RA_FOE_STATE_FIN     = 3,
};

enum ra_foe_pkt_type {
	RA_FOE_IPV4_HNAPT = 0,
	RA_FOE_IPV4_HNAT  = 1,
};

enum ra_foe_l4_type {
	RA_FOE_TCP = 0,
	RA_FOE_UDP = 1,
};

/*
 * FOE information block 1.
 *
 * Bits 26..31 have the same meaning in UNBIND and BIND/FIN state.
 * The lower bits differ depending on the state.
 */
#define RA_FOE_IB1_PKT_TYPE		GENMASK(27, 26)
#define RA_FOE_IB1_STATE		GENMASK(29, 28)
#define RA_FOE_IB1_UDP			BIT(30)
#define RA_FOE_IB1_STATIC		BIT(31)

/* UNBIND IB1 */
#define RA_FOE_IB1_UNB_TIMESTAMP	GENMASK(7, 0)
#define RA_FOE_IB1_UNB_PKT_COUNT	GENMASK(23, 8)

/* BIND / FIN IB1 */
#define RA_FOE_IB1_BIND_TIMESTAMP	GENMASK(15, 0)
#define RA_FOE_IB1_VLAN1_ACTION		GENMASK(17, 16)
#define RA_FOE_IB1_VLAN2_ACTION		GENMASK(19, 18)
#define RA_FOE_IB1_SNAP_ACTION		GENMASK(21, 20)
#define RA_FOE_IB1_PPPOE_ACTION		GENMASK(23, 22)
#define RA_FOE_IB1_TTL			BIT(24)
#define RA_FOE_IB1_KEEPALIVE		BIT(25)

/* state = UNBIND */
struct ra_foe_ud_info1 {
	u32 time_stamp:8;
	u32 pcnt:16;
	u32 resv:2;
	u32 pkt_type:2;
	u32 state:2;
	u32 udp:1;
	u32 sta:1;
};

/* state = BIND / FIN */
struct ra_foe_bf_info1 {
	u16 time_stamp;

	u16 v1:2;
	u16 v2:2;
	u16 snap:2;
	u16 pppoe:2;
	u16 ttl:1;
	u16 ka:1;
	u16 pkt_type:2;
	u16 state:2;
	u16 udp:1;
	u16 sta:1;
};

struct ra_foe_info2 {
	u16 fd:1;
	u16 dp:3;
	u16 fp:1;
	u16 up:3;
	u16 port_mg:6;
	u16 resv:1;
	u16 me:1;

	u16 port_ag:6;
	u16 drm:1;
	u16 ae:1;
	u16 dscp:8;
};

/*
 * PPEv1 IPv4 HNAT/HNAPT entry.
 */
struct ra_foe_ipv4_hnapt {
	union {
		struct ra_foe_ud_info1 udib1;
		struct ra_foe_bf_info1 bfib1;
		u32 info_blk1;
	};

	u32 sip;
	u32 dip;

	u16 dport;
	u16 sport;

	union {
		struct ra_foe_info2 iblk2;
		u32 info_blk2;
	};

	u32 new_sip;
	u32 new_dip;

	u16 new_dport;
	u16 new_sport;

	u8 dmac_hi[2];
	u16 vlan1;
	u8 dmac_lo[4];

	u8 smac_hi[2];
	u16 pppoe_id;
	u8 smac_lo[4];

	u8 snap_ctrl[3];
	u8 act_dp:6;
	u8 resv1:2;

	u16 vlan2;
	u16 resv2;

	u32 resv3;
	u32 resv4;
};

struct ra_foe_entry {
	union {
		/*
		 * All PPEv1 entry formats start with information block 1.
		 * Expose it directly so state transitions can use one atomic
		 * 32-bit hardware-word update instead of a C bitfield RMW.
		 */
		u32 info_blk1;
		struct ra_foe_bf_info1 bfib1;
		struct ra_foe_ipv4_hnapt ipv4_hnapt;
	};
};

static_assert(sizeof(struct ra_foe_entry) == RA_FOE_ENTRY_SIZE);
static_assert(offsetof(struct ra_foe_entry, info_blk1) == 0);
static_assert(offsetof(struct ra_foe_ipv4_hnapt, info_blk1) == 0);

enum ra_ppe_action {
	RA_PPE_ACT_NONE		= 0,
	RA_PPE_ACT_MODIFY	= 1,
	RA_PPE_ACT_INSERT	= 2,
	RA_PPE_ACT_DELETE	= 3,
};

/*
 * PPEv1 MAC packing.
 *
 * MAC addresses are not stored linearly in the FOE table.
 */
static inline void ra_foe_set_mac(u8 *dst, const u8 *mac)
{
	dst[1] = mac[0];
	dst[0] = mac[1];
	dst[7] = mac[2];
	dst[6] = mac[3];
	dst[5] = mac[4];
	dst[4] = mac[5];
}

static inline void ra_foe_get_mac(u8 *mac, const u8 *src)
{
	mac[0] = src[1];
	mac[1] = src[0];
	mac[2] = src[7];
	mac[3] = src[6];
	mac[4] = src[5];
	mac[5] = src[4];
}

static inline enum ra_foe_state
ra_foe_state(const struct ra_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_FOE_IB1_STATE, ib1);
}

static inline bool ra_foe_is_unbind(const struct ra_foe_entry *foe)
{
	return ra_foe_state(foe) == RA_FOE_STATE_UNBIND;
}

static inline bool ra_foe_is_ipv4_hnapt(const struct ra_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_FOE_IB1_PKT_TYPE, ib1) ==
	       RA_FOE_IPV4_HNAPT;
}

static inline bool ra_foe_is_ipv4_hnat(const struct ra_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_FOE_IB1_PKT_TYPE, ib1) ==
	       RA_FOE_IPV4_HNAT;
}

#endif
