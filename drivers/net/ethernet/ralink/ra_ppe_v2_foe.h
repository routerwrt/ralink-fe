/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_V2_FOE_H
#define _RA_PPE_V2_FOE_H

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/types.h>

/*
 * Ralink/MediaTek HNATv2 FOE definitions.
 *
 * HNATv2 supports several additional entry formats, but this driver
 * deliberately limits its initial scope to:
 *
 *   - IPv4 HNAT/HNAPT
 *   - IPv6 5-tuple routing
 *
 * The FOE table is always configured for 80-byte entries, allowing both
 * IPv4 and IPv6 5-tuple entries without changing the table format.
 */
#define RA_PPE_V2_FOE_ENTRY_SIZE	80

#define RA_PPE_V2_IB2_FPIDX		GENMASK(3, 0)
/*
 * FPIDX value which leaves egress selection to normal switch lookup.
 */
#define RA_PPE_V2_FPIDX_LOOKUP		8

enum ra_ppe_v2_foe_state {
	RA_PPE_V2_FOE_STATE_INVALID = 0,
	RA_PPE_V2_FOE_STATE_UNBIND  = 1,
	RA_PPE_V2_FOE_STATE_BIND    = 2,
	RA_PPE_V2_FOE_STATE_FIN     = 3,
};

enum ra_ppe_v2_foe_type {
	RA_PPE_V2_FOE_IPV4_HNAPT	= 0,
	RA_PPE_V2_FOE_IPV4_HNAT		= 1,
	RA_PPE_V2_FOE_IPV6_5T_ROUTE	= 5,
};

/*
 * FOE information block 1.
 *
 * Bits 25..31 have the same meaning in UNBIND and BIND/FIN state.
 * Lower bits have state-dependent interpretations.
 */
#define RA_PPE_V2_IB1_PKT_TYPE		GENMASK(27, 25)
#define RA_PPE_V2_IB1_STATE		GENMASK(29, 28)
#define RA_PPE_V2_IB1_UDP		BIT(30)
#define RA_PPE_V2_IB1_STATIC		BIT(31)

/* UNBIND IB1 */
#define RA_PPE_V2_IB1_UNB_TIMESTAMP	GENMASK(7, 0)
#define RA_PPE_V2_IB1_UNB_PKT_COUNT	GENMASK(23, 8)
#define RA_PPE_V2_IB1_UNB_PREB		BIT(24)

/* BIND / FIN IB1 */
#define RA_PPE_V2_IB1_BIND_TIMESTAMP	GENMASK(14, 0)
#define RA_PPE_V2_IB1_KEEPALIVE		BIT(15)
#define RA_PPE_V2_IB1_VLAN_LAYER	GENMASK(18, 16)
#define RA_PPE_V2_IB1_PPPOE		BIT(19)
#define RA_PPE_V2_IB1_DVP		BIT(20)
#define RA_PPE_V2_IB1_DRM		BIT(21)
#define RA_PPE_V2_IB1_CACHE		BIT(22)
#define RA_PPE_V2_IB1_RMT		BIT(23)
#define RA_PPE_V2_IB1_TTL		BIT(24)

/*
 * FOE information block 2, HNATv2 layout.
 */
#define RA_PPE_V2_IB2_FPIDX		GENMASK(3, 0)
#define RA_PPE_V2_IB2_FP		BIT(4)
#define RA_PPE_V2_IB2_UP		GENMASK(7, 5)
#define RA_PPE_V2_IB2_FDQ		GENMASK(11, 8)
#define RA_PPE_V2_IB2_PORT_MG		GENMASK(17, 12)
#define RA_PPE_V2_IB2_PORT_AG		GENMASK(23, 18)
#define RA_PPE_V2_IB2_DSCP		GENMASK(31, 24)

/*
 * User-defined field.
 *
 * Bits 31..26 contain the vendor ACT_DP field. Its use is not required
 * by the current offload path.
 */
#define RA_PPE_V2_ACT_DP		GENMASK(31, 26)

/*
 * IPv4 HNAT/HNAPT descriptor.
 *
 * Both IPv4 HNAT and HNAPT use this hardware layout and differ only in
 * the packet type encoded in information block 1.
 */
struct ra_ppe_v2_foe_ipv4 {
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

	u32 resv1;
	u32 resv2;

	u32 udf;

	u16 vlan1;
	u16 etype;

	u8 dmac_hi[4];

	u16 vlan2;
	u8 dmac_lo[2];

	u8 smac_hi[4];

	u16 pppoe_id;
	u8 smac_lo[2];
};

/*
 * IPv6 5-tuple routing descriptor.
 *
 * HNATv2 does not rewrite the IPv6 addresses in this format. The
 * complete original IPv6 source/destination tuple and transport ports
 * form the hardware flow key.
 */
struct ra_ppe_v2_foe_ipv6_5t {
	u32 info_blk1;

	u32 sip[4];
	u32 dip[4];

	u16 dport;
	u16 sport;

	u32 resv1;
	u32 resv2;
	u32 resv3;

	u32 udf;

	u32 info_blk2;

	u16 vlan1;
	u16 etype;

	u8 dmac_hi[4];

	u16 vlan2;
	u8 dmac_lo[2];

	u8 smac_hi[4];

	u16 pppoe_id;
	u8 smac_lo[2];
};

struct ra_ppe_v2_foe_entry {
	union {
		u32 info_blk1;
		struct ra_ppe_v2_foe_ipv4 ipv4;
		struct ra_ppe_v2_foe_ipv6_5t ipv6_5t;
	};
};

static_assert(sizeof(struct ra_ppe_v2_foe_ipv4) == 64);
static_assert(sizeof(struct ra_ppe_v2_foe_ipv6_5t) == 80);
static_assert(sizeof(struct ra_ppe_v2_foe_entry) ==
	      RA_PPE_V2_FOE_ENTRY_SIZE);

static_assert(offsetof(struct ra_ppe_v2_foe_entry, info_blk1) == 0);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv4, info_blk1) == 0);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv6_5t, info_blk1) == 0);

/*
 * Useful fixed offsets for checking the descriptor against the vendor
 * layout.
 */
static_assert(offsetof(struct ra_ppe_v2_foe_ipv4, info_blk2) == 16);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv4, udf) == 40);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv4, vlan1) == 44);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv4, dmac_hi) == 48);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv4, smac_hi) == 56);

static_assert(offsetof(struct ra_ppe_v2_foe_ipv6_5t, udf) == 52);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv6_5t, info_blk2) == 56);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv6_5t, vlan1) == 60);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv6_5t, dmac_hi) == 64);
static_assert(offsetof(struct ra_ppe_v2_foe_ipv6_5t, smac_hi) == 72);

/*
 * MAC packing helpers.
 */
static inline void
ra_ppe_v2_foe_set_mac(u8 *hi, u8 *lo, const u8 *mac)
{
	hi[3] = mac[0];
	hi[2] = mac[1];
	hi[1] = mac[2];
	hi[0] = mac[3];

	lo[1] = mac[4];
	lo[0] = mac[5];
}

static inline void
ra_ppe_v2_foe_get_mac(u8 *mac, const u8 *hi, const u8 *lo)
{
	mac[0] = hi[3];
	mac[1] = hi[2];
	mac[2] = hi[1];
	mac[3] = hi[0];

	mac[4] = lo[1];
	mac[5] = lo[0];
}

static inline enum ra_ppe_v2_foe_state
ra_ppe_v2_foe_state(const struct ra_ppe_v2_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_PPE_V2_IB1_STATE, ib1);
}

static inline bool
ra_ppe_v2_foe_is_unbind(const struct ra_ppe_v2_foe_entry *foe)
{
	return ra_ppe_v2_foe_state(foe) ==
	       RA_PPE_V2_FOE_STATE_UNBIND;
}

static inline enum ra_ppe_v2_foe_type
ra_ppe_v2_foe_type(const struct ra_ppe_v2_foe_entry *foe)
{
	u32 ib1 = READ_ONCE(foe->info_blk1);

	return FIELD_GET(RA_PPE_V2_IB1_PKT_TYPE, ib1);
}

static inline bool
ra_ppe_v2_foe_is_ipv4_hnapt(const struct ra_ppe_v2_foe_entry *foe)
{
	return ra_ppe_v2_foe_type(foe) ==
	       RA_PPE_V2_FOE_IPV4_HNAPT;
}

static inline bool
ra_ppe_v2_foe_is_ipv4_hnat(const struct ra_ppe_v2_foe_entry *foe)
{
	return ra_ppe_v2_foe_type(foe) ==
	       RA_PPE_V2_FOE_IPV4_HNAT;
}

static inline bool
ra_ppe_v2_foe_is_ipv4(const struct ra_ppe_v2_foe_entry *foe)
{
	enum ra_ppe_v2_foe_type type = ra_ppe_v2_foe_type(foe);

	return type == RA_PPE_V2_FOE_IPV4_HNAPT ||
	       type == RA_PPE_V2_FOE_IPV4_HNAT;
}

static inline bool
ra_ppe_v2_foe_is_ipv6_5t(const struct ra_ppe_v2_foe_entry *foe)
{
	return ra_ppe_v2_foe_type(foe) ==
	       RA_PPE_V2_FOE_IPV6_5T_ROUTE;
}

#endif
