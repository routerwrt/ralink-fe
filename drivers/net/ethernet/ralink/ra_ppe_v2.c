// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/kernel.h>

#include "ra_ppe.h"
#include "ra_ppe_offload.h"
#include "ra_ppe_v2_foe.h"
#include "ra_ppe_v2_regs.h"

/*
 * HNATv2 policy defaults.
 *
 * The initial implementation deliberately follows the PPEv1 hardware
 * learning model:
 *
 *   MISS -> CPU + build UNBIND
 *        -> HIT_UNBIND_RATE_REACH
 *        -> Linux authorizes exact tuple
 *        -> software promotes learned FOE slot to BIND
 */
#define RA_PPE_V2_BIND_RATE_PPS		30

#define RA_PPE_V2_KA_TIMER_VAL		1
#define RA_PPE_V2_TCP_KA_VAL		1
#define RA_PPE_V2_UDP_KA_VAL		1

#define RA_PPE_V2_UNBIND_TIMEOUT	3
#define RA_PPE_V2_UNBIND_MIN_PACKETS	1000

#define RA_PPE_V2_TCP_TIMEOUT		5
#define RA_PPE_V2_UDP_TIMEOUT		5
#define RA_PPE_V2_FIN_TIMEOUT		5

/*
 * Keep the same conservative occupancy policy as PPEv1.
 *
 * These values are software policy rather than part of the HNATv2
 * descriptor ABI.
 */
#define RA_PPE_V2_QUARTER_LIMIT		100
#define RA_PPE_V2_HALF_LIMIT		50
#define RA_PPE_V2_FULL_LIMIT		25

struct ra_ppe_v2_foe_config {
	enum ra_ppe_v2_tbl_size tbl_size;
};

static int
ra_ppe_v2_get_foe_config(u32 entries, struct ra_ppe_v2_foe_config *cfg)
{
	switch (entries) {
	case 1024:
		cfg->tbl_size = RA_PPE_V2_TBL_1K;
		break;
	case 2048:
		cfg->tbl_size = RA_PPE_V2_TBL_2K;
		break;
	case 4096:
		cfg->tbl_size = RA_PPE_V2_TBL_4K;
		break;
	case 8192:
		cfg->tbl_size = RA_PPE_V2_TBL_8K;
		break;
	case 16384:
		cfg->tbl_size = RA_PPE_V2_TBL_16K;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void ra_ppe_v2_clear_table(struct ra_ppe *ppe)
{
	size_t size;

	size = (size_t)ppe->foe_entries * ppe->foe_entry_size;

	memset(ppe->foe_table, 0, size);

	/*
	 * Coherent DMA removes cache maintenance, not ordering.
	 */
	dma_wmb();
}

static void ra_ppe_v2_set_bind_rate(struct ra_ppe *ppe, u32 pps)
{
	ra_ppe_m32(ppe, RA_V2_REG_PPE_BNDR,
		   RA_PPE_V2_BIND_RATE,
		   FIELD_PREP(RA_PPE_V2_BIND_RATE, pps));
}

static void
ra_ppe_v2_set_entry_limits(struct ra_ppe *ppe, u16 full,
			   u16 half, u16 quarter)
{
	ra_ppe_w32(ppe, RA_V2_REG_PPE_BIND_LMT_0,
		   FIELD_PREP(RA_PPE_V2_BIND_LMT0_QUARTER, quarter) |
		   FIELD_PREP(RA_PPE_V2_BIND_LMT0_HALF, half));

	ra_ppe_m32(ppe, RA_V2_REG_PPE_BIND_LMT_1,
		   RA_PPE_V2_BIND_LMT1_FULL,
		   FIELD_PREP(RA_PPE_V2_BIND_LMT1_FULL, full));
}

static void
ra_ppe_v2_set_ka_interval(struct ra_ppe *ppe, u16 timer,
			  u8 tcp, u8 udp)
{
	u32 mask, val;

	mask = RA_PPE_V2_KA_TIMER |
	       RA_PPE_V2_KA_TCP |
	       RA_PPE_V2_KA_UDP;

	val = FIELD_PREP(RA_PPE_V2_KA_TIMER, timer) |
	      FIELD_PREP(RA_PPE_V2_KA_TCP, tcp) |
	      FIELD_PREP(RA_PPE_V2_KA_UDP, udp);

	ra_ppe_m32(ppe, RA_V2_REG_PPE_KA, mask, val);
}

static void
ra_ppe_v2_set_unbind_age(struct ra_ppe *ppe, u16 min_packets,
			 u8 timeout)
{
	u32 mask, val;

	mask = RA_PPE_V2_UNB_AGE_MIN_PKT |
	       RA_PPE_V2_UNB_AGE_DELTA;

	val = FIELD_PREP(RA_PPE_V2_UNB_AGE_MIN_PKT, min_packets) |
	      FIELD_PREP(RA_PPE_V2_UNB_AGE_DELTA, timeout);

	ra_ppe_m32(ppe, RA_V2_REG_PPE_UNB_AGE, mask, val);
}

static void
ra_ppe_v2_set_bind_age(struct ra_ppe *ppe, u16 tcp_timeout,
		       u16 udp_timeout, u16 fin_timeout)
{
	u32 mask, val;

	/*
	 * Keep these helpers separate from PPEv1 even where the register
	 * layout happens to overlap. The two generations have independent
	 * register definitions by design.
	 */
	mask = RA_PPE_V2_BND_AGE0_UDP;
	val = FIELD_PREP(RA_PPE_V2_BND_AGE0_UDP, udp_timeout);

	ra_ppe_m32(ppe, RA_V2_REG_PPE_BND_AGE_0, mask, val);

	mask = RA_PPE_V2_BND_AGE1_TCP |
	       RA_PPE_V2_BND_AGE1_FIN;

	val = FIELD_PREP(RA_PPE_V2_BND_AGE1_TCP, tcp_timeout) |
	      FIELD_PREP(RA_PPE_V2_BND_AGE1_FIN, fin_timeout);

	ra_ppe_m32(ppe, RA_V2_REG_PPE_BND_AGE_1, mask, val);
}

static void
ra_ppe_v2_config_table(struct ra_ppe *ppe,
		       const struct ra_ppe_v2_foe_config *cfg)
{
	u32 mask, val;

	/*
	 * HNATv2 table configuration:
	 *
	 *   bits 2:0   table size
	 *   bit  3     80-byte entry format
	 *   bits 5:4   search-miss action
	 *   bits 15:14 hash mode
	 *
	 * Always use 80-byte entries. This is a hardware table property,
	 * not something conditional on CONFIG_IPV6.
	 */
	mask = RA_PPE_V2_TB_ENTRY_NUM |
	       RA_PPE_V2_TB_ENTRY_SIZE |
	       RA_PPE_V2_TB_MISS_ACTION |
	       RA_PPE_V2_TB_UNB_AGE_EN |
	       RA_PPE_V2_TB_TCP_AGE_EN |
	       RA_PPE_V2_TB_UDP_AGE_EN |
	       RA_PPE_V2_TB_FIN_AGE_EN |
	       RA_PPE_V2_TB_KA_CFG |
	       RA_PPE_V2_TB_HASH_MODE;

	val = FIELD_PREP(RA_PPE_V2_TB_ENTRY_NUM, cfg->tbl_size) |
	      RA_PPE_V2_TB_ENTRY_SIZE |
	      FIELD_PREP(RA_PPE_V2_TB_MISS_ACTION,
			 RA_PPE_V2_MISS_CPU_BUILD) |
	      RA_PPE_V2_TB_UNB_AGE_EN |
	      RA_PPE_V2_TB_TCP_AGE_EN |
	      RA_PPE_V2_TB_UDP_AGE_EN |
	      RA_PPE_V2_TB_FIN_AGE_EN |
	      FIELD_PREP(RA_PPE_V2_TB_KA_CFG,
			 RA_PPE_V2_KA_UC_OLD_HDR) |
	      FIELD_PREP(RA_PPE_V2_TB_HASH_MODE,
			 RA_PPE_V2_HASH_MODE_1);

	ra_ppe_m32(ppe, RA_V2_REG_PPE_TB_CFG, mask, val);

	ra_ppe_w32(ppe, RA_V2_REG_PPE_HASH_SEED,
		   RA_PPE_V2_HASH_SEED);
}

static void ra_ppe_v2_config_flow(struct ra_ppe *ppe)
{
	u32 mask, val;

	/*
	 * Initial scope:
	 *
	 *   - unicast FOE lookup
	 *   - IPv4 HNAPT/NAT
	 *
	 * Do not enable broadcast, multicast or IPv6 processing until the
	 * basic IPv4 datapath is proven.
	 */
	mask = RA_PPE_V2_FUC_FOE |
	       RA_PPE_V2_IPV4_NAT_EN |
	       RA_PPE_V2_IPV4_NAPT_EN;

	val = mask;

	ra_ppe_m32(ppe, RA_V2_REG_PPE_FLOW_CFG, mask, val);
}

static void ra_ppe_v2_disable_flows(struct ra_ppe *ppe)
{
	u32 mask;

	mask = RA_PPE_V2_FBC_FOE |
	       RA_PPE_V2_FMC_FOE |
	       RA_PPE_V2_FUC_FOE |
	       RA_PPE_V2_IPV6_3T_ROUTE_EN |
	       RA_PPE_V2_IPV6_5T_ROUTE_EN |
	       RA_PPE_V2_IPV6_6RD_EN |
	       RA_PPE_V2_IPV4_NAT_EN |
	       RA_PPE_V2_IPV4_NAPT_EN |
	       RA_PPE_V2_IPV4_DSLITE_EN;

	ra_ppe_m32(ppe, RA_V2_REG_PPE_FLOW_CFG, mask, 0);
}

static void ra_ppe_v2_config_global(struct ra_ppe *ppe)
{
	/*
	 * MT7620 vendor code does not use PPE_GLO_CFG bit 0 as an engine
	 * enable. Do not import the PPEv1 RA_PPE_GLO_EN interpretation.
	 *
	 * TTL0_DROP remains clear so exceptional TTL packets are returned
	 * toward the CPU path rather than silently discarded.
	 */
	ra_ppe_m32(ppe, RA_V2_REG_PPE_GLO_CFG,
		   RA_PPE_V2_TTL0_DROP, 0);
}

static int ra_ppe_v2_hw_init(struct ra_ppe *ppe)
{
	struct ra_ppe_v2_foe_config cfg;
	int err;

	err = ra_ppe_v2_get_foe_config(ppe->foe_entries, &cfg);
	if (err) {
		dev_err(ppe->dev,
			"unsupported PPEv2 FOE table size: %u\n",
			ppe->foe_entries);
		return err;
	}

	if (WARN_ON_ONCE(upper_32_bits((u64)ppe->foe_phys)))
		return -ERANGE;

	/*
	 * Start from a quiescent PPE configuration. GSW steering should not
	 * yet be active, but also make bootloader leftovers harmless.
	 */
	ra_ppe_v2_disable_flows(ppe);

	/*
	 * Publish no usable descriptor state before the complete table has
	 * been initialized.
	 */
	ra_ppe_v2_clear_table(ppe);

	ra_ppe_w32(ppe, RA_V2_REG_PPE_TB_BASE,
		   lower_32_bits(ppe->foe_phys));

	ra_ppe_v2_config_table(ppe, &cfg);

	ra_ppe_v2_set_bind_rate(ppe, RA_PPE_V2_BIND_RATE_PPS);

	ra_ppe_v2_set_entry_limits(ppe,
				   RA_PPE_V2_FULL_LIMIT,
				   RA_PPE_V2_HALF_LIMIT,
				   RA_PPE_V2_QUARTER_LIMIT);

	ra_ppe_v2_set_ka_interval(ppe,
				  RA_PPE_V2_KA_TIMER_VAL,
				  RA_PPE_V2_TCP_KA_VAL,
				  RA_PPE_V2_UDP_KA_VAL);

	ra_ppe_v2_set_unbind_age(ppe,
				 RA_PPE_V2_UNBIND_MIN_PACKETS,
				 RA_PPE_V2_UNBIND_TIMEOUT);

	ra_ppe_v2_set_bind_age(ppe,
			       RA_PPE_V2_TCP_TIMEOUT,
			       RA_PPE_V2_UDP_TIMEOUT,
			       RA_PPE_V2_FIN_TIMEOUT);

	ra_ppe_v2_config_global(ppe);

	/*
	 * FLOW_CFG is programmed last on the PPE side. Once GSW steering is
	 * subsequently enabled, hardware may immediately start constructing
	 * UNBIND entries.
	 */
	ra_ppe_v2_config_flow(ppe);

	dma_wmb();

	dev_info(ppe->dev,
		 "Ralink PPEv2 initialized, FOE table=%u entries\n",
		 ppe->foe_entries);

	return 0;
}

static void ra_ppe_v2_hw_deinit(struct ra_ppe *ppe)
{
	if (!ppe)
		return;

	/*
	 * GSW steering must already have been disabled before the FOE table
	 * can be released.
	 */
	ra_ppe_v2_disable_flows(ppe);

	ra_ppe_offload_reset(ppe);
}

const struct ra_ppe_ops ra_ppe_v2_ops = {
	.init			= ra_ppe_v2_hw_init,
	.deinit			= ra_ppe_v2_hw_deinit,

	/*
	 * PPEv2 remains valid for the FE/PPE device lifetime. The GSW-side
	 * P7/TPF/ACL path owns ingress gating.
	 */
	.start			= NULL,
	.stop			= NULL,

	.offload		= &ra_ppe_v2_offload_ops,
	.foe_entry_size		= sizeof(struct ra_ppe_v2_foe_entry),

	.cpu_reason_unbind_rate	=
		RA_PPE_V2_REASON_HIT_UNBIND_RATE_REACH,

	.cpu_reason_keepalive	=
		RA_PPE_V2_REASON_HIT_BIND_KA_UC_OLD_HDR,
};
