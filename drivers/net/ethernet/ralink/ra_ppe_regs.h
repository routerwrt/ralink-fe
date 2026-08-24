/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RA_PPE_REGS_H
#define _RA_PPE_REGS_H

#include <linux/bits.h>

/*
 * Ralink PPEv1 / HNATv1
 *
 * Register offsets are relative to RALINK_FRAME_ENGINE_BASE.
 *
 * PPEv1 supports IPv4 NAT/NAPT only.  Do not reuse these definitions
 * for HNATv2/PPEv2; several register layouts and bit definitions differ.
 */

#define RA_REG_FOE_TS			0x001c

#define RA_REG_GDMA1_FWD_CFG		0x0020
#define RA_REG_GDMA2_FWD_CFG		0x0060

#define RA_REG_PPE_GLO_CFG		0x0200
#define RA_REG_PPE_FLOW_SET		0x0214
#define RA_REG_PPE_FOE_CFG		0x0230
#define RA_REG_PPE_FOE_BASE		0x0234
#define RA_REG_PPE_FOE_USE		0x0238
#define RA_REG_PPE_FOE_BNDR		0x023c
#define RA_REG_PPE_FOE_LMT1		0x0240
#define RA_REG_PPE_FOE_LMT2		0x0244
#define RA_REG_PPE_FOE_KA		0x0248
#define RA_REG_PPE_FOE_UNB_AGE		0x024c
#define RA_REG_PPE_FOE_BND_AGE0	0x0250
#define RA_REG_PPE_FOE_BND_AGE1	0x0254

/* PPE_GLO_CFG */
#define RA_PPE_GLO_EN			BIT(0)
#define RA_PPE_TTL0_DROP		BIT(4)
#define RA_PPE_VPRI_EN			BIT(8)
#define RA_PPE_DPRI_EN			BIT(9)
#define RA_PPE_REG_VPRI			BIT(10)
#define RA_PPE_REG_DSCP			BIT(11)
#define RA_PPE_RED_MODE_MASK		GENMASK(13, 12)
#define RA_PPE_ACL_PRI_EN		BIT(14)

/* PPE_FLOW_SET, PPEv1 */
#define RA_PPE_FBC_FOE			BIT(2)
#define RA_PPE_FMC_FOE			BIT(10)
#define RA_PPE_FUC_FOE			BIT(18)
#define RA_PPE_IPV6_FOE_EN		BIT(24)
#define RA_PPE_IPV6_PE_EN		BIT(25)
#define RA_PPE_IPV4_NAT_EN		BIT(26)
#define RA_PPE_IPV4_NAPT_EN		BIT(27)

/*
 * GDMA forwarding configuration.
 *
 * Each destination field is three bits wide.  Destination 6 routes
 * traffic through PPEv1.
 */
#define RA_GDM_FWD_CPU			0
#define RA_GDM_FWD_GDMA1		1
#define RA_GDM_FWD_PPE			6

#define RA_GDM_OFRC_SHIFT		0
#define RA_GDM_MFRC_SHIFT		4
#define RA_GDM_BFRC_SHIFT		8
#define RA_GDM_UFRC_SHIFT		12

#define RA_GDM_FRC_MASK(_shift)		GENMASK((_shift) + 2, (_shift))
#define RA_GDM_FRC_VAL(_val, _shift)	((_val) << (_shift))

#define RA_GDM_ALL_FRC_MASK					\
	(RA_GDM_FRC_MASK(RA_GDM_OFRC_SHIFT) |			\
	 RA_GDM_FRC_MASK(RA_GDM_MFRC_SHIFT) |			\
	 RA_GDM_FRC_MASK(RA_GDM_BFRC_SHIFT) |			\
	 RA_GDM_FRC_MASK(RA_GDM_UFRC_SHIFT))

#define RA_GDM_ALL_FRC_PPE					\
	(RA_GDM_FRC_VAL(RA_GDM_FWD_PPE, RA_GDM_OFRC_SHIFT) |	\
	 RA_GDM_FRC_VAL(RA_GDM_FWD_PPE, RA_GDM_MFRC_SHIFT) |	\
	 RA_GDM_FRC_VAL(RA_GDM_FWD_PPE, RA_GDM_BFRC_SHIFT) |	\
	 RA_GDM_FRC_VAL(RA_GDM_FWD_PPE, RA_GDM_UFRC_SHIFT))

/* PPE_FOE_CFG */
#define RA_FOE_TBL_SIZE_MASK		GENMASK(2, 0)
#define RA_FOE_HASH_MODE		BIT(3)
#define RA_FOE_MISS_MASK		GENMASK(5, 4)

#define RA_FOE_UNB_AGE_EN		BIT(8)
#define RA_FOE_TCP_AGE_EN		BIT(9)
#define RA_FOE_UDP_AGE_EN		BIT(10)
#define RA_FOE_FIN_AGE_EN		BIT(11)

/*
 * PPEv1 bit 12 selects the keepalive packet header:
 *
 *   0 = rewritten/new header
 *   1 = original header
 *
 * Keepalive generation itself is enabled separately by bit 13.
 *
 * HNATv2 expands the header mode field to two bits, so these definitions
 * are intentionally PPEv1-specific.
 */
#define RA_FOE_KA_ORIGINAL_HEADER	BIT(12)
#define RA_FOE_KA_EN			BIT(13)

#define RA_FOE_MISS_DROP		0
#define RA_FOE_MISS_FORWARD		1
#define RA_FOE_MISS_CPU			2
#define RA_FOE_MISS_CPU_BUILD		3

/* PPE_FOE_LMT1 */
#define RA_FOE_LMT1_QUARTER_MASK	GENMASK(13, 0)
#define RA_FOE_LMT1_HALF_MASK		GENMASK(29, 16)

/* PPE_FOE_LMT2 */
#define RA_FOE_LMT2_FULL_MASK		GENMASK(13, 0)

/*
 * Throttle creation of new UNBIND entries as the FOE table fills.
 *
 * These values match the original vendor Kconfig defaults.  Unlike the
 * vendor build, which later disabled this throttling by programming the
 * maximum 14-bit value, retaining the limits helps prevent transient or
 * unauthorized traffic from exhausting the hardware table.
 */
#define RA_PPE_FOE_QUARTER_LIMIT	100
#define RA_PPE_FOE_HALF_LIMIT		50
#define RA_PPE_FOE_FULL_LIMIT		25

/*
 * PPE_FOE_KA
 *
 * PPE scans FOE entries using KA_TIMER in millisecond units.
 * The effective per-entry keepalive interval additionally depends on
 * the configured FOE table size.
 */
#define RA_FOE_KA_TIMER_MASK		GENMASK(15, 0)
#define RA_FOE_KA_TCP_MASK		GENMASK(23, 16)
#define RA_FOE_KA_UDP_MASK		GENMASK(31, 24)

/*
 * PPE_FOE_UNB_AGE
 *
 * An UNBIND entry whose packet count is below MIN_PACKETS and whose idle
 * time exceeds DELTA is eligible for aging.
 */
#define RA_FOE_UNB_AGE_DELTA_MASK	GENMASK(7, 0)
#define RA_FOE_UNB_AGE_MIN_PKT_MASK	GENMASK(31, 16)

/* PPE_FOE_BND_AGE0 */
#define RA_FOE_BND_AGE0_UDP_MASK	GENMASK(15, 0)

/* PPE_FOE_BND_AGE1 */
#define RA_FOE_BND_AGE1_TCP_MASK	GENMASK(15, 0)
#define RA_FOE_BND_AGE1_FIN_MASK	GENMASK(31, 16)

enum ra_foe_tbl_size {
	RA_FOE_TBL_1K,
	RA_FOE_TBL_2K,
	RA_FOE_TBL_4K,
	RA_FOE_TBL_8K,
	RA_FOE_TBL_16K,
};

enum ra_ppe_cpu_reason {
	RA_PPE_REASON_TTL_0			= 0x80,
	RA_PPE_REASON_NOT_IPV4_HLEN5		= 0x90,
	RA_PPE_REASON_NOT_TCP_UDP_L4_READY	= 0x91,
	RA_PPE_REASON_TCP_SYN_FIN_RST		= 0x92,
	RA_PPE_REASON_UN_HIT			= 0x93,
	RA_PPE_REASON_HIT_UNBIND		= 0x94,
	RA_PPE_REASON_HIT_UNBIND_RATE_REACH	= 0x95,
	RA_PPE_REASON_HIT_FIN			= 0x96,
	RA_PPE_REASON_HIT_BIND_TTL_1		= 0x97,
	RA_PPE_REASON_HIT_BIND_KEEPALIVE	= 0x98,
	RA_PPE_REASON_HIT_BIND_FORCE_TO_CPU	= 0x99,
	RA_PPE_REASON_ACL_FOE_TBL_ERR		= 0x9a,
	RA_PPE_REASON_ACL_TBL_TTL_1		= 0x9b,
	RA_PPE_REASON_ACL_ALERT_CPU		= 0x9c,
	RA_PPE_REASON_NO_FORCE_DEST_PORT	= 0xa0,
	RA_PPE_REASON_EXCEED_MTU		= 0xa1,
};

#endif
