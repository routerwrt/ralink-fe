// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/kernel.h>

#include "ra_ppe.h"
#include "ra_ppe_foe.h"
#include "ra_ppe_offload.h"
#include "ra_ppe_v1_regs.h"

/*
 * PPEv1 policy defaults from the original Ralink HNAT driver.
 *
 * These remain driver-local rather than Kconfig options. FOE table size
 * itself is selected by SoC data.
 */
#define RA_PPE_BIND_RATE_PPS		30

#define RA_PPE_KA_TIMER			1

#define RA_PPE_UNBIND_TIMEOUT		3
#define RA_PPE_UNBIND_MIN_PACKETS	1000

#define RA_PPE_TCP_TIMEOUT		5
#define RA_PPE_UDP_TIMEOUT		5
#define RA_PPE_FIN_TIMEOUT		5

struct ra_ppe_foe_config {
	enum ra_foe_tbl_size tbl_size;

	/*
	 * Vendor TCP/UDP KA multiplier for this table size.
	 *
	 * Effective nominal intervals with KA_TIMER=1 are:
	 *
	 *	1K	5 seconds
	 *	2K	6 seconds
	 *	4K	4 seconds
	 *	8K	8 seconds
	 *	16K	16 seconds
	 */
	u8 ka_interval;
};

static int
ra_ppe_v1_get_foe_config(u32 entries, struct ra_ppe_foe_config *cfg)
{
	switch (entries) {
	case 1024:
		cfg->tbl_size = RA_FOE_TBL_1K;
		cfg->ka_interval = 5;
		break;
	case 2048:
		cfg->tbl_size = RA_FOE_TBL_2K;
		cfg->ka_interval = 3;
		break;
	case 4096:
		cfg->tbl_size = RA_FOE_TBL_4K;
		cfg->ka_interval = 1;
		break;
	case 8192:
		cfg->tbl_size = RA_FOE_TBL_8K;
		cfg->ka_interval = 1;
		break;
	case 16384:
		cfg->tbl_size = RA_FOE_TBL_16K;
		cfg->ka_interval = 1;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void ra_ppe_v1_set_gdma_fwd(struct ra_ppe *ppe, bool enable)
{
	ra_ppe_m32(ppe, RA_REG_GDMA1_FWD_CFG,
		   RA_GDM_ALL_FRC_MASK,
		   enable ? RA_GDM_ALL_FRC_PPE : 0);
}

static void ra_ppe_v1_enable_foe(struct ra_ppe *ppe, bool enable)
{
	u32 mask;

	/*
	 * PPEv1 offload supported by this driver is IPv4 NAT/NAPT only.
	 * IPv6 support belongs to PPEv2/HNATv2 and must not leak into
	 * the PPEv1 implementation.
	 */
	mask = RA_PPE_IPV4_NAPT_EN |
	       RA_PPE_IPV4_NAT_EN |
	       RA_PPE_FUC_FOE |
	       RA_PPE_FMC_FOE |
	       RA_PPE_FBC_FOE;

	ra_ppe_m32(ppe, RA_REG_PPE_FLOW_SET,
		   mask, enable ? mask : 0);
}

static void ra_ppe_v1_config_engine(struct ra_ppe *ppe)
{
	u32 mask, val;

	mask = RA_PPE_TTL0_DROP |
	       RA_PPE_VPRI_EN |
	       RA_PPE_DPRI_EN |
	       RA_PPE_ACL_PRI_EN |
	       RA_PPE_RED_MODE_MASK;

	/*
	 * PPEv1 vendor defaults:
	 *
	 * TTL0_DROP = 0:
	 *	TTL-expired packets are sent to the CPU instead of being
	 *	dropped silently by PPE.
	 *
	 * VPRI/DPRI/ACL priority handling is enabled and RED mode is 1.
	 */
	val = RA_PPE_VPRI_EN |
	      RA_PPE_DPRI_EN |
	      RA_PPE_ACL_PRI_EN |
	      FIELD_PREP(RA_PPE_RED_MODE_MASK, 1);

	ra_ppe_m32(ppe, RA_REG_PPE_GLO_CFG, mask, val);
}

static void ra_ppe_v1_enable_engine(struct ra_ppe *ppe, bool enable)
{
	ra_ppe_m32(ppe, RA_REG_PPE_GLO_CFG,
		   RA_PPE_GLO_EN,
		   enable ? RA_PPE_GLO_EN : 0);
}

static void ra_ppe_v1_set_bind_rate(struct ra_ppe *ppe, u32 pps)
{
	/*
	 * PPE_FOE_BNDR is the packet-per-second threshold which causes an
	 * UNBIND entry to report HIT_UNBIND_RATE_REACH.
	 */
	ra_ppe_w32(ppe, RA_REG_PPE_FOE_BNDR, pps);
}

static void
ra_ppe_v1_set_max_entry_limit(struct ra_ppe *ppe, u16 full,
			      u16 half, u16 quarter)
{
	ra_ppe_w32(ppe, RA_REG_PPE_FOE_LMT1,
		   FIELD_PREP(RA_FOE_LMT1_QUARTER_MASK, quarter) |
		   FIELD_PREP(RA_FOE_LMT1_HALF_MASK, half));

	ra_ppe_w32(ppe, RA_REG_PPE_FOE_LMT2,
		   FIELD_PREP(RA_FOE_LMT2_FULL_MASK, full));
}

static void
ra_ppe_v1_set_ka_interval(struct ra_ppe *ppe, u16 timer,
			  u8 tcp, u8 udp)
{
	u32 mask, val;

	mask = RA_FOE_KA_TIMER_MASK |
	       RA_FOE_KA_TCP_MASK |
	       RA_FOE_KA_UDP_MASK;

	val = FIELD_PREP(RA_FOE_KA_TIMER_MASK, timer) |
	      FIELD_PREP(RA_FOE_KA_TCP_MASK, tcp) |
	      FIELD_PREP(RA_FOE_KA_UDP_MASK, udp);

	ra_ppe_m32(ppe, RA_REG_PPE_FOE_KA, mask, val);
}

static void
ra_ppe_v1_set_unbind_age(struct ra_ppe *ppe, u16 min_packets,
			 u8 timeout)
{
	u32 mask, val;

	mask = RA_FOE_UNB_AGE_MIN_PKT_MASK |
	       RA_FOE_UNB_AGE_DELTA_MASK;

	val = FIELD_PREP(RA_FOE_UNB_AGE_MIN_PKT_MASK, min_packets) |
	      FIELD_PREP(RA_FOE_UNB_AGE_DELTA_MASK, timeout);

	ra_ppe_m32(ppe, RA_REG_PPE_FOE_UNB_AGE, mask, val);
}

static void
ra_ppe_v1_set_bind_age(struct ra_ppe *ppe, u16 tcp_timeout,
		       u16 udp_timeout, u16 fin_timeout)
{
	u32 val;

	ra_ppe_m32(ppe, RA_REG_PPE_FOE_BND_AGE0,
		   RA_FOE_BND_AGE0_UDP_MASK,
		   FIELD_PREP(RA_FOE_BND_AGE0_UDP_MASK,
			      udp_timeout));

	val = FIELD_PREP(RA_FOE_BND_AGE1_TCP_MASK, tcp_timeout) |
	      FIELD_PREP(RA_FOE_BND_AGE1_FIN_MASK, fin_timeout);

	ra_ppe_m32(ppe, RA_REG_PPE_FOE_BND_AGE1,
		   RA_FOE_BND_AGE1_TCP_MASK |
		   RA_FOE_BND_AGE1_FIN_MASK,
		   val);
}

static void
ra_ppe_v1_config_foe(struct ra_ppe *ppe,
		     const struct ra_ppe_foe_config *cfg)
{
	u32 mask, val;

	/*
	 * PPEv1 learning model:
	 *
	 *   packet miss
	 *        |
	 *        v
	 *   CPU + build UNBIND
	 *        |
	 *        v
	 *   hardware measures flow rate
	 *        |
	 *        v
	 *   HIT_UNBIND_RATE_REACH
	 *        |
	 *        v
	 *   Linux verifies exact flow authorization
	 *        |
	 *        v
	 *   promote learned FOE entry to BIND
	 *
	 * Software deliberately does not reproduce the undocumented PPE
	 * hashing/collision algorithm. Hardware supplies the FOE index.
	 */

	mask = RA_FOE_TBL_SIZE_MASK |
	       RA_FOE_HASH_MODE |
	       RA_FOE_MISS_MASK |
	       RA_FOE_UNB_AGE_EN |
	       RA_FOE_TCP_AGE_EN |
	       RA_FOE_UDP_AGE_EN |
	       RA_FOE_FIN_AGE_EN |
	       RA_FOE_KA_ORIGINAL_HEADER |
	       RA_FOE_KA_EN;

	val = FIELD_PREP(RA_FOE_TBL_SIZE_MASK, cfg->tbl_size) |
	      RA_FOE_HASH_MODE |
	      FIELD_PREP(RA_FOE_MISS_MASK, RA_FOE_MISS_CPU_BUILD) |
	      RA_FOE_UNB_AGE_EN |
	      RA_FOE_TCP_AGE_EN |
	      RA_FOE_UDP_AGE_EN |
	      RA_FOE_FIN_AGE_EN |
	      RA_FOE_KA_EN;

	/*
	 * RA_FOE_KA_ORIGINAL_HEADER deliberately remains clear.
	 *
	 * PPEv1 vendor default:
	 *
	 *	0 = keepalive packet with rewritten/new header
	 *	1 = keepalive packet with original header
	 */
	ra_ppe_m32(ppe, RA_REG_PPE_FOE_CFG, mask, val);

	ra_ppe_v1_set_bind_rate(ppe, RA_PPE_BIND_RATE_PPS);

	ra_ppe_v1_set_max_entry_limit(ppe,
				      RA_PPE_FOE_FULL_LIMIT,
				      RA_PPE_FOE_HALF_LIMIT,
				      RA_PPE_FOE_QUARTER_LIMIT);

	ra_ppe_v1_set_ka_interval(ppe, RA_PPE_KA_TIMER,
				  cfg->ka_interval,
				  cfg->ka_interval);

	ra_ppe_v1_set_unbind_age(ppe,
				 RA_PPE_UNBIND_MIN_PACKETS,
				 RA_PPE_UNBIND_TIMEOUT);

	ra_ppe_v1_set_bind_age(ppe,
			       RA_PPE_TCP_TIMEOUT,
			       RA_PPE_UDP_TIMEOUT,
			       RA_PPE_FIN_TIMEOUT);
}

static void ra_ppe_v1_foe_clear_all(struct ra_ppe *ppe)
{
	size_t size;

	size = (size_t)ppe->foe_entries * ppe->foe_entry_size;

	memset(ppe->foe_table, 0, size);
	dma_wmb();
}

static int ra_ppe_v1_start(struct ra_ppe *ppe)
{
	struct ra_ppe_foe_config cfg;
	int err;

	if (!ppe || !ppe->foe_table)
		return -EINVAL;

	err = ra_ppe_v1_get_foe_config(ppe->foe_entries, &cfg);
	if (err) {
		dev_err(ppe->dev, "unsupported PPEv1 FOE table size: %u\n",
			ppe->foe_entries);
		return err;
	}

	/*
	 * Begin from a quiescent hardware state. This also makes start()
	 * independent of firmware/bootloader leftovers.
	 */
	ra_ppe_v1_set_gdma_fwd(ppe, false);
	ra_ppe_v1_enable_engine(ppe, false);
	ra_ppe_v1_enable_foe(ppe, false);

	/*
	 * Any previous FOE index association is invalid after this clear.
	 * Keep Linux's authorized exact tuples, but forget their old hardware
	 * slots so they can be learned and rebound after restart.
	 */
	ra_ppe_offload_reset(ppe);

	ra_ppe_v1_foe_clear_all(ppe);

	if (WARN_ON_ONCE(upper_32_bits((u64)ppe->foe_phys)))
		return -ERANGE;

	ra_ppe_w32(ppe, RA_REG_PPE_FOE_BASE,
		   lower_32_bits(ppe->foe_phys));

	ra_ppe_v1_config_foe(ppe, &cfg);
	ra_ppe_v1_config_engine(ppe);

	/*
	 * Ensure coherent table initialization is globally visible before
	 * PPE can consume it.
	 */
	dma_wmb();

	ra_ppe_v1_enable_foe(ppe, true);
	ra_ppe_v1_enable_engine(ppe, true);

	/*
	 * Last step: once GDMA forwards packets to PPE, RX may immediately
	 * start reporting PPE CPU reasons and learned FOE indices.
	 */
	ra_ppe_v1_set_gdma_fwd(ppe, true);

	dev_info(ppe->dev,
		 "Ralink PPEv1 started, FOE table=%u entries\n",
		 ppe->foe_entries);

	return 0;
}

static void ra_ppe_v1_stop(struct ra_ppe *ppe)
{
	if (!ppe)
		return;

	/*
	 * Prevent new packets from entering PPE before changing engine state.
	 */
	ra_ppe_v1_set_gdma_fwd(ppe, false);

	ra_ppe_v1_enable_engine(ppe, false);
	ra_ppe_v1_enable_foe(ppe, false);

	/*
	 * Hardware FOE indices must not survive a stop/start cycle as valid
	 * software associations.
	 */
	ra_ppe_offload_reset(ppe);
}

const struct ra_ppe_ops ra_ppe_v1_ops = {
	.start			= ra_ppe_v1_start,
	.stop			= ra_ppe_v1_stop,
	.offload		= &ra_ppe_v1_offload_ops,
	.foe_entry_size		= sizeof(struct ra_foe_entry),
	.cpu_reason_unbind_rate	= RA_PPE_REASON_HIT_UNBIND_RATE_REACH,
	.cpu_reason_keepalive	= RA_PPE_REASON_HIT_BIND_KEEPALIVE,
};
