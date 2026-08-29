/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_V1_FOE_H
#define _RA_PPE_V1_FOE_H

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/types.h>

#define RA_PPE_V1_FOE_ENTRY_SIZE	64

enum ra_ppe_v1_foe_state {
	RA_PPE_V1_FOE_STATE_INVALID = 0,
	RA_PPE_V1_FOE_STATE_UNBIND  = 1,
	RA_PPE_V1_FOE_STATE_BIND    = 2,
	RA_PPE_V1_FOE_STATE_FIN     = 3,
};

enum ra_ppe_v1_foe_type {
	RA_PPE_V1_FOE_IPV4_HNAPT = 0,
	RA_PPE_V1_FOE_IPV4_HNAT  = 1,
};

enum ra_ppe_v1_l4_type {
	RA_PPE_V1_TCP = 0,
	RA_PPE_V1_UDP = 1,
};

enum ra_ppe_v1_action {
	RA_PPE_V1_ACT_NONE	= 0,
	RA_PPE_V1_ACT_MODIFY	= 1,
	RA_PPE_V1_ACT_INSERT	= 2,
	RA_PPE_V1_ACT_DELETE	= 3,
};

/*
 * PPEv1 FOE information block 1.
 *
 * Bits 26..31 have the same meaning in UNBIND and BIND/FIN state.
 * The lower bits have state-dependent interpretations.
 */
#define RA_PPE_V1_IB1_PKT_TYPE		GENMASK(27, 26)
#define RA_PPE_V1_IB1_STATE		GENMASK(29, 28)
#define RA_PPE_V1_IB1_UDP		BIT(30)
#define RA_PPE_V1_IB1_STATIC		BIT(31)

/* UNBIND IB1 */
#define RA_PPE_V1_IB1_UNB_TIMESTAMP	GENMASK(7, 0)
#define RA_PPE_V1_IB1_UNB_PKT_COUNT	GENMASK(23, 8)

/* BIND / FIN IB1 */
#define RA_PPE_V1_IB1_BIND_TIMESTAMP	GENMASK(15, 0)
#define RA_PPE_V1_IB1_VLAN1_ACTION	GENMASK(17, 16)
#define RA_PPE_V1_IB1_VLAN2_ACTION	GENMASK(19, 18)
#define RA_PPE_V1_IB1_SNAP_ACTION	GENMASK(21, 20)
#define RA_PPE_V1_IB1_PPPOE_ACTION	GENMASK(23, 22)
#define RA_PPE_V1_IB1_TTL		BIT(24)
#define RA_PPE_V1_IB1_KEEPALIVE		BIT(25)

/*
 * PPEv1 FOE information block 2.
 */
#define RA_PPE_V1_IB2_FD		BIT(0)
#define RA_PPE_V1_IB2_DP		GENMASK(3, 1)
#define RA_PPE_V1_IB2_FP		BIT(4)
#define RA_PPE_V1_IB2_UP		GENMASK(7, 5)
#define RA_PPE_V1_IB2_PORT_MG		GENMASK(13, 8)
#define RA_PPE_V1_IB2_ME		BIT(15)
#define RA_PPE_V1_IB2_PORT_AG		GENMASK(21, 16)
#define RA_PPE_V1_IB2_DRM		BIT(22)
#define RA_PPE_V1_IB2_AE		BIT(23)
#define RA_PPE_V1_IB2_DSCP		GENMASK(31, 24)

/*
 * PPEv1 IPv4 HNAT/HNAPT FOE entry.
 *
 * HNAT and HNAPT use the same descriptor layout and are distinguished
 * by the packet type encoded in information block 1.
 */
struct ra_ppe_v1_foe_ipv4 {
	u32 info_blk1;

	u32 sip;
	u32 dip;

	u16 dport;
	u16 sport;

	u32 info_blk2;

	u32 new_sip;
	u32 new_dip;

	u16 new_dport;
	u16 new_sport;

	/*
	 * PPEv1 stores MAC addresses in a non-linear hardware layout.
	 */
	u8 dmac_hi[2];
	u16 vlan1;
	u8 dmac_lo[4];

	u8 smac_hi[2];
	u16 pppoe_id;
	u8 smac_lo[4];

	u8 snap_ctrl[3];
	u8 act_dp;

	u16 vlan2;
	u16 resv2;

	u32 resv3;
	u32 resv4;
};

struct ra_ppe_v1_foe_entry {
	union {
		/*
		 * All PPEv1 formats begin with information block 1.
		 * Expose it directly so state transitions can use one atomic
		 * 32-bit hardware-word update.
		 */
		u32 info_blk1;

		struct ra_ppe_v1_foe_ipv4 ipv4;
	};
};

static_assert(sizeof(struct ra_ppe_v1_foe_entry) ==
	      RA_PPE_V1_FOE_ENTRY_SIZE);
static_assert(offsetof(struct ra_ppe_v1_foe_entry, info_blk1) == 0);
static_assert(offsetof(struct ra_ppe_v1_foe_ipv4, info_blk1) == 0);

/*
 * PPEv1 MAC packing.
 *
 * MAC addresses are not stored linearly in the FOE entry.
 */
static inline void
ra_ppe_v1_foe_set_mac(u8 *dst, const u8 *mac)
{
	dst[1] = mac[0];
	dst[0] = mac[1];

	dst[7] = mac[2];
	dst[6] = mac[3];
	dst[5] = mac[4];
	dst[4] = mac[5];
}

static inline void
ra_ppe_v1_foe_get_mac(u8 *mac, const u8 *src)
{
	mac[0] = src[1];
	mac[1] = src[0];

	mac[2] = src[7];
	mac[3] = src[6];
	mac[4] = src[5];
	mac[5] = src[4];
}

static inline enum ra_ppe_v1_foe_state
ra_ppe_v1_foe_state(const struct ra_ppe_v1_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_PPE_V1_IB1_STATE, ib1);
}

static inline bool
ra_ppe_v1_foe_is_unbind(const struct ra_ppe_v1_foe_entry *foe)
{
	return ra_ppe_v1_foe_state(foe) ==
	       RA_PPE_V1_FOE_STATE_UNBIND;
}

static inline bool
ra_ppe_v1_foe_is_ipv4_hnapt(const struct ra_ppe_v1_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_PPE_V1_IB1_PKT_TYPE, ib1) ==
	       RA_PPE_V1_FOE_IPV4_HNAPT;
}

static inline bool
ra_ppe_v1_foe_is_ipv4_hnat(const struct ra_ppe_v1_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_PPE_V1_IB1_PKT_TYPE, ib1) ==
	       RA_PPE_V1_FOE_IPV4_HNAT;
}

#endif
